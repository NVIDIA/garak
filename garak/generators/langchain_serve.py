import logging
import json
import requests
import os
from typing import List, Union
from urllib.parse import urlparse

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


class LangChainServeLLMGenerator(Generator):
    """Class supporting LangChain Serve LLM interfaces via HTTP POST requests.

    This class facilitates communication with LangChain Serve's LLMs through a web API, making it possible
    to utilize external LLMs not directly integrated into the LangChain library. It requires setting up
    an API endpoint using LangChain Serve.

    Utilizes the HTTP POST method to send prompts to the specified LLM and retrieves the generated text
    response. It is necessary to ensure that the API endpoint is correctly set up and accessible.

    Inherits from Garak's base Generator class, extending its capabilities to support web-based LLM services.
    The API endpoint is set through the 'LANGCHAIN_SERVE_URI' environment variable, which should be the base URI
    of the LangChain Serve deployment. The 'invoke' endpoint is then appended to this URI to form the full API endpoint URL.

    Example of setting up the environment variable:
        export LANGCHAIN_SERVE_URI=http://127.0.0.1:8000/rag-chroma-private
    """

    generator_family_name = "LangChainServe"
    ENV_VAR = "LANGCHAIN_SERVE_URI"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {"config_hash": "default"}

    config_hash = "default"

    def __init__(
        self, name=None, config_root=_config
    ):  # name not required, will be extracted from uri
        self.uri = None
        self._load_config(config_root)
        self.name = self.uri.split("/")[-1]
        self.fullname = f"LangChain Serve LLM {self.name}"
        self.api_endpoint = f"{self.uri}/invoke"

        super().__init__(self.name, config_root=config_root)

    def _validate_env_var(self):
        if self.uri is None and hasattr(self, "key_env_var"):
            self.uri = os.getenv(self.key_env_var)
        if not self._validate_uri(self.uri):
            raise ValueError("Invalid API endpoint URI")

    @staticmethod
    def _validate_uri(uri):
        """Validates the given URI for correctness."""
        try:
            result = urlparse(uri)
            return all([result.scheme, result.netloc])
        except Exception as e:
            logging.error(f"URL parsing error: {e}")
            return False

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = -1
    ) -> List[Union[Message, None]]:
        """Makes an HTTP POST request to the LangChain Serve API endpoint to invoke the LLM with a given prompt."""
        # Should this be expanded to process a whole conversation in some way?
        prompt_text = prompt.last_message().text
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        payload = {"input": prompt_text, "config": {}, "kwargs": {}}

        try:
            response = requests.post(
                f"{self.api_endpoint}?config_hash={self.config_hash}",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if 400 <= response.status_code < 500:
                logging.error(f"Client error for prompt {prompt_text}: {e}")
                return [None]
            elif 500 <= response.status_code < 600:
                logging.error(f"Server error for prompt {prompt_text}: {e}")
                raise
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return [None]

        try:
            response_data = response.json()
            if "output" not in response_data:
                logging.error(f"No output found in response: {response_data}")
                return [None]
            return [Message(response_data.get("output")[0])]
        except json.JSONDecodeError as e:
            logging.error(
                f"Failed to decode JSON from response: {response.text}, error: {e}"
            )
            return [None]
        except Exception as e:
            logging.error(f"Unexpected error processing response: {e}")
            return [None]


DEFAULT_CLASS = "LangChainServeLLMGenerator"
