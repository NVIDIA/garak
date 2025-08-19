from garak import _config
from garak.attempt import Message, Turn, Conversation
from garak.generators.base import Generator
from typing import List, Union
import os
import requests


class WatsonXGenerator(Generator):
    """This is a generator for watsonx.ai.

    Make sure that you initialize the environment variables:
        'WATSONX_TOKEN',
        'WATSONX_URL',
        'WATSONX_PROJECTID' OR 'WATSONX_DEPLOYID'.

    To use a model that is in the "project" stage initialize the WATSONX_PROJECTID variable with the Project ID of the model.
    To use a tuned model that is deployed, simply initialize the WATSONX_DEPLOYID variable with the Deployment ID of the model.
    """

    ENV_VAR = "WATSONX_TOKEN"
    URI_ENV_VAR = "WATSONX_URL"
    PID_ENV_VAR = "WATSONX_PROJECTID"
    DID_ENV_VAR = "WATSONX_DEPLOYID"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": None,
        "version": "2023-05-29",
        "project_id": "",
        "deployment_id": "",
        "prompt_variable": "input",
        "bearer_token": "",
        "max_tokens": 900,
    }

    generator_family_name = "watsonx"

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)
        # Initialize and validate api_key
        if self.api_key is not None:
            os.environ[self.ENV_VAR] = self.api_key

    def _set_bearer_token(self, iam_url="https://iam.cloud.ibm.com/identity/token"):
        header = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        body = (
            "grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=" + self.api_key
        )
        response = requests.post(url=iam_url, headers=header, data=body)
        self.bearer_token = "Bearer " + response.json()["access_token"]

    def _generate_with_project(self, payload):
        # Generation via Project ID.

        url = self.uri + f"/ml/v1/text/generation?version={self.version}"

        body = {
            "input": payload,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": self.max_tokens,
                "min_new_tokens": 0,
                "repetition_penalty": 1,
            },
            "model_id": self.name,
            "project_id": self.project_id,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self.bearer_token,
        }

        response = requests.post(url=url, headers=headers, json=body)
        return response.json()

    def _generate_with_deployment(self, payload):
        # Generation via Deployment ID.
        url = (
            self.uri
            + "/ml/v1/deployments/"
            + self.deployment_id
            + f"/text/generation?version={self.version}"
        )
        body = {"parameters": {"prompt_variables": {self.prompt_variable: payload}}}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.bearer_token,
        }
        response = requests.post(url=url, headers=headers, json=body)
        return response.json()

    def _validate_env_var(self):
        # Initialize and validate url.
        if self.uri is not None:
            pass
        else:
            self.uri = os.getenv("WATSONX_URL", None)
            if self.uri is None:
                raise ValueError(
                    f"The {self.URI_ENV_VAR} environment variable is required. Please enter the URL corresponding to the region of your provisioned service instance. \n"
                )

        # Initialize and validate project_id.
        if self.project_id:
            pass
        else:
            self.project_id = os.getenv("WATSONX_PROJECTID", "")

        # Initialize and validate deployment_id.
        if self.deployment_id:
            pass
        else:
            self.deployment_id = os.getenv("WATSONX_DEPLOYID", "")

        # Check to ensure at least ONE of project_id or deployment_id is populated.
        if not self.project_id and not self.deployment_id:
            raise ValueError(
                f"Either {self.PID_ENV_VAR} or {self.DID_ENV_VAR} is required. Please supply either a Project ID or Deployment ID. \n"
            )
        return super()._validate_env_var()

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if not self.bearer_token:
            self._set_bearer_token()

        # Check if message is empty. If it is, append null byte.
        if not prompt or not prompt.last_message().text:
            prompt = Conversation([Turn("user", Message("\x00"))])
            print(
                "WARNING: Empty prompt was found. Null byte character appended to prevent API failure."
            )

        # can this support a Conversation?
        output = ""
        if self.deployment_id:
            output = self._generate_with_deployment(prompt.last_message().text)
        else:
            output = self._generate_with_project(prompt.last_message().text)

        # Parse the output to only contain the output message from the model. Return a list containing that message.
        return [Message("".join(output["results"][0]["generated_text"]))]


DEFAULT_CLASS = "WatsonXGenerator"
