from garak import _config
from garak.generators.base import Generator
from typing import List, Union
import os
import importlib


class WatsonXGenerator(Generator):
    """
    This is a generator for watsonx.ai.

    Make sure that you initialize the environment variables: 
        'WATSONX_TOKEN', 
        'WATSONX_URL', 
        and 'WATSONX_PROJECTID'.
    
    To use a tuned model that is deployed, use 'deployment/deployment' for the -n flag and make sure
    to also initialize the 'WATSONX_DEPLOYID' environment variable.
    """

    ENV_VAR = "WATSONX_TOKEN"
    URI_ENV_VAR = "WATSONX_URL"
    PID_ENV_VAR = "WATSONX_PROJECTID"
    DID_ENV_VAR = "WATSONX_DEPLOYID"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": None,
        "project_id": None,
        "deployment_id": None,
        "frequency_penalty": 0.5,
        "logprobs": True,
        "top_logprobs": 3,
        "presence_penalty": 0.3,
        "temperature": 0.7,
        "max_tokens": 100,
        "time_limit": 300000,
        "top_p": 0.9,
        "n": 1,
    }

    generator_family_name = "watsonx"

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)

        # Initialize and validate api_key
        if self.api_key is not None:
            os.environ[self.ENV_VAR] = self.api_key

        # Initialize and validate url.
        if self.uri is not None:
            pass
        else :
            self.uri = os.getenv("WATSONX_URL", None)
            if self.uri is None:
                raise ValueError(
                    f"The {self.URI_ENV_VAR} environment variable is required. Please enter the URL corresponding to the region of your provisioned service instance. \n"
                )
        # Initialize and validate project_id.
        if self.project_id is not None:
            pass
        else :
            self.project_id = os.getenv("WATSONX_PROJECTID", None)
            if self.project_id is None:
                raise ValueError(
                    f"The {self.PID_ENV_VAR} environment variable is required. Please enter the corresponding Project ID of the resource. \n"
                )

        # Import Foundation Models from ibm_watsonx_ai module. Import the Credentials function from the same module.
        self.watsonx = importlib.import_module("ibm_watsonx_ai.foundation_models")
        self.Credentials = getattr(
            importlib.import_module("ibm_watsonx_ai"), "Credentials"
        )

    def get_model(self):
        # Call Credentials function with the url and api_key.
        credentials = self.Credentials(url=self.uri, api_key=self.api_key)
        if self.name == "deployment/deployment":
            self.deployment_id = os.getenv("WATSONX_DEPLOYID", None)
            if self.deployment_id is None:
                raise ValueError(
                    f"The {self.DID_ENV_VAR} environment variable is required. Please enter the corresponding Deployment ID of the resource. \n"
                )

            return self.watsonx.ModelInference(
                deployment_id=self.deployment_id,
                credentials=credentials,
                project_id=self.project_id,
            )

        else:
            return self.watsonx.ModelInference(
                model_id=self.name,
                credentials=credentials,
                project_id=self.project_id,
                params=self.watsonx.schema.TextChatParameters(
                    frequency_penalty=self.frequency_penalty,
                    logprobs=self.logprobs,
                    top_logprobs=self.top_logprobs,
                    presence_penalty=self.presence_penalty,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    time_limit=self.time_limit,
                    top_p=self.top_p,
                    n=self.n,
                ),
            )

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:

        # Get/Create Model
        model = self.get_model()

        # Check if message is empty. If it is, append null byte.
        if not prompt:
            prompt = "\x00"
            print(
                "WARNING: Empty prompt was found. Null byte character appended to prevent API failure."
            )

        # Parse the output to only contain the output message from the model. Return a list containing that message.
        return ["".join(model.generate(prompt=prompt)["results"][0]["generated_text"])]


DEFAULT_CLASS = "WatsonXGenerator"
