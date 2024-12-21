"""Azure OpenAI generator

Supports chat + chatcompletion models. Put your API key in the AZURE_API_KEY environment variable, 
the azure openai endpoint in the AZURE_ENDPOINT environment variable and the azure openai model name 
in AZURE_MODEL_NAME environment variable.

Put the deployment name in either the --model_name command line parameter, or
pass it as an argument to the Generator constructor.
"""

import os
import openai

from garak.generators.openai import (
    OpenAICompatible,
    chat_models,
    completion_models,
    context_lengths,
)

# lists derived from https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/models
# some azure openai model names should be mapped to openai names
openai_model_mapping = {
    "gpt-4": "gpt-4-turbo-2024-04-09",
    "gpt-35-turbo": "gpt-3.5-turbo-0125",
    "gpt-35-turbo-16k": "gpt-3.5-turbo-16k",
    "gpt-35-turbo-instruct": "gpt-3.5-turbo-instruct",
}


class AzureOpenAIGenerator(OpenAICompatible):
    """Wrapper for Azure Open AI. Expects AZURE_API_KEY, AZURE_ENDPOINT and AZURE_MODEL_NAME environment variables.

    Uses the [OpenAI-compatible API](https://learn.microsoft.com/en-us/azure/ai-services/openai/api-version-deprecation)
    via direct HTTP request.

    To get started with this generator:
    #. Visit [https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/models](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/models) and find the LLM you'd like to use.
    #. [Deploy a model](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/create-resource?pivots=web-portal#deploy-a-model) and copy paste the model and deployment names.
    #. On the Azure portal page for the Azure OpenAI you want to use click on "Resource Management -> Keys and Endpoint" and copy paste the API Key and endpoint.
    #. In your console, Set the ``AZURE_API_KEY``, ``AZURE_ENDPOINT`` and ``AZURE_MODEL_NAME`` variables.
    #. Run garak, setting ``--model_type`` to ``azure`` and ``--model_name`` to the name **of the deployment**.
    - e.g. ``gpt-4o``.
    """

    ENV_VAR = "AZURE_API_KEY"
    MODEL_NAME_ENV_VAR = "AZURE_MODEL_NAME"
    ENDPOINT_ENV_VAR = "AZURE_ENDPOINT"

    active = True
    generator_family_name = "Azure"
    api_version = "2024-06-01"

    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "model_name": None,
        "uri": None,
    }

    def _validate_env_var(self):
        if self.model_name is None:
            if not hasattr(self, "model_name_env_var"):
                self.model_name_env_var = self.MODEL_NAME_ENV_VAR

            self.model_name = os.getenv(self.model_name_env_var, None)

            if self.model_name is None:
                raise ValueError(
                    f"The {self.MODEL_NAME_ENV_VAR} environment variable is required.\n"
                )

        if self.uri is None:
            if not hasattr(self, "endpoint_env_var"):
                self.endpoint_env_var = self.ENDPOINT_ENV_VAR

            self.uri = os.getenv(self.endpoint_env_var, None)

            if self.uri is None:
                raise ValueError(
                    f"The {self.ENDPOINT_ENV_VAR} environment variable is required.\n"
                )

        return super()._validate_env_var()

    def _load_client(self):
        if self.model_name in openai_model_mapping:
            self.model_name = openai_model_mapping[self.model_name]

        self.client = openai.AzureOpenAI(
            azure_endpoint=self.uri, api_key=self.api_key, api_version=self.api_version
        )

        if self.name == "":
            raise ValueError(
                f"Deployment name is required for {self.generator_family_name}, use --model_name"
            )

        if self.model_name in completion_models:
            self.generator = self.client.completions
        elif self.model_name in chat_models:
            self.generator = self.client.chat.completions
        elif "-".join(self.model_name.split("-")[:-1]) in chat_models and re.match(
            r"^.+-[01][0-9][0-3][0-9]$", self.model_name
        ):  # handle model names -MMDDish suffix
            self.generator = self.client.completions
        else:
            raise ValueError(
                f"No {self.generator_family_name} API defined for '{self.model_name}' in generators/openai.py - please add one!"
            )

        if self.model_name in context_lengths:
            self.context_len = context_lengths[self.model_name]


DEFAULT_CLASS = "AzureOpenAIGenerator"
