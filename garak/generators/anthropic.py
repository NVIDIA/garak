"""Anthropic Claude generator for garak"""

import logging
from typing import List, Union

import anthropic
import backoff

from garak.generators.base import Generator
from garak.exception import APIKeyMissingError


DEFAULT_CLASS = "AnthropicGenerator"


class AnthropicGenerator(Generator):
    """Interface for Anthropic Claude models via API."""

    ENV_VAR = "ANTHROPIC_API_KEY"

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS

    generator_family_name = "Anthropic"
    supports_multiple_generations = False

    def _load_client(self):
        """Load the Anthropic client."""
        if not self.api_key:
            raise APIKeyMissingError(
                f"Put the Anthropic API key in the {self.ENV_VAR} environment variable (this was empty)\n"
                f"e.g.: export {self.ENV_VAR}='sk-ant-api03-...'"
            )
        self.client = anthropic.Anthropic(api_key=self.api_key)

    def _clear_client(self):
        """Clear the client to enable pickling."""
        self.client = None

    # avoid attempt to pickle the client attribute
    def __getstate__(self) -> object:
        self._clear_client()
        return dict(self.__dict__)

    # restore the client attribute
    def __setstate__(self, d) -> object:
        self.__dict__.update(d)
        self._load_client()

    def _validate_config(self):
        """Validate configuration."""
        if self.name in ("", None):
            raise ValueError(
                f"{self.generator_family_name} requires model name to be set, e.g. --model_name claude-3-haiku-20240307"
            )

    def __init__(self, name="", config_root=None):
        if config_root is None:
            from garak import _config

            config_root = _config

        self.name = name
        self._load_config(config_root)
        self.fullname = f"{self.generator_family_name}:{self.name}"
        self.context_len = 200000  # All Anthropic Claude models support 200k context

        self._load_client()
        self._validate_config()

        super().__init__(self.name, config_root=config_root)

        # Clear client config to enable object to pickle
        self._clear_client()

    @backoff.on_exception(
        backoff.fibo,
        (
            anthropic.BadRequestError,
            anthropic.RateLimitError,
            anthropic.APITimeoutError,
        ),
        max_value=70,
    )
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Call Anthropic Claude API."""
        if self.client is None:
            # Reload client once when consuming the generator
            self._load_client()

        create_args = {
            "model": self.name,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": getattr(self, "max_tokens", 150),
        }

        # Add temperature if it's explicitly set (otherwise let Anthropic use its default)
        if hasattr(self, "temperature") and getattr(self, "temperature") is not None:
            create_args["temperature"] = getattr(self, "temperature")

        try:
            if self.client is None:
                logging.error("Client is None, cannot make API call")
                return [None]
            response = self.client.messages.create(**create_args)

            if response.content and len(response.content) > 0:
                return [
                    content.text
                    for content in response.content
                    if hasattr(content, "text")
                ]
            else:
                logging.warning("No content in response")
                return [None]

        except Exception as e:
            logging.exception(f"Error calling Anthropic API: {str(e)}")
            return [None]