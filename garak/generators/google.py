"""Gemini generator interface using google-genai SDK

Expects API key in GOOGLE_API_KEY environment variable (Gemini Developer API).

Example usage:
- --model_type gemini --model_name gemini-2.0-flash-001
"""

from typing import List, Union
import logging

import backoff

from garak.generators.base import Generator
from garak.exception import APIKeyMissingError

# Imports for Google Gen AI SDK
try:
    from google import genai
    from google.api_core import exceptions as gapi_exceptions
    from google.genai import types as genai_types
except Exception as e:  # pragma: no cover - import error surfaced at runtime when used
    genai = None
    gapi_exceptions = None
    genai_types = None
    _import_error = e
else:
    _import_error = None

# Define backoff exceptions tuple safely at import time
if gapi_exceptions is not None:
    BACKOFF_EXCS = (
        gapi_exceptions.TooManyRequests,
        gapi_exceptions.ServiceUnavailable,
        gapi_exceptions.InternalServerError,
        gapi_exceptions.DeadlineExceeded,
        gapi_exceptions.GoogleAPICallError,
    )
else:  # fallback when sdk not present at import time
    BACKOFF_EXCS = (Exception,)

# Context length mapping for Gemini models
context_lengths = {
    "embedding-gecko-001": 1024,
    "gemini-1.5-pro-latest": 2000000,
    "gemini-1.5-pro-002": 2000000,
    "gemini-1.5-pro": 2000000,
    "gemini-1.5-flash-latest": 1000000,
    "gemini-1.5-flash": 1000000,
    "gemini-1.5-flash-002": 1000000,
    "gemini-1.5-flash-8b": 1000000,
    "gemini-1.5-flash-8b-001": 1000000,
    "gemini-1.5-flash-8b-latest": 1000000,
    "gemini-2.5-pro-preview-03-25": 1048576,
    "gemini-2.5-flash-preview-05-20": 1048576,
    "gemini-2.5-flash": 1048576,
    "gemini-2.5-flash-lite-preview-06-17": 1048576,
    "gemini-2.5-pro-preview-05-06": 1048576,
    "gemini-2.5-pro-preview-06-05": 1048576,
    "gemini-2.5-pro": 1048576,
    "gemini-2.0-flash-exp": 1048576,
    "gemini-2.0-flash": 1048576,
    "gemini-2.0-flash-001": 1048576,
    "gemini-2.0-flash-exp-image-generation": 1048576,
    "gemini-2.0-flash-lite-001": 1048576,
    "gemini-2.0-flash-lite": 1048576,
    "gemini-2.0-flash-preview-image-generation": 32768,
    "gemini-2.0-flash-lite-preview-02-05": 1048576,
    "gemini-2.0-flash-lite-preview": 1048576,
    "gemini-2.0-pro-exp": 1048576,
    "gemini-2.0-pro-exp-02-05": 1048576,
    "gemini-exp-1206": 1048576,
    "gemini-2.0-flash-thinking-exp-01-21": 1048576,
    "gemini-2.0-flash-thinking-exp": 1048576,
    "gemini-2.0-flash-thinking-exp-1219": 1048576,
    "gemini-2.5-flash-preview-tts": 8192,
    "gemini-2.5-pro-preview-tts": 8192,
    "learnlm-2.0-flash-experimental": 1048576,
    "gemma-3-1b-it": 32768,
    "gemma-3-4b-it": 32768,
    "gemma-3-12b-it": 32768,
    "gemma-3-27b-it": 131072,
    "gemma-3n-e4b-it": 8192,
    "gemma-3n-e2b-it": 8192,
    "gemini-2.5-flash-lite": 1048576,
    "embedding-001": 2048,
    "text-embedding-004": 2048,
    "gemini-embedding-exp-03-07": 8192,
    "gemini-embedding-exp": 8192,
    "gemini-embedding-001": 2048,
    "aqa": 7168,
    "imagen-3.0-generate-002": 480,
    "imagen-4.0-generate-preview-06-06": 480,
}

DEFAULT_CLASS = "GoogleGenerator"


class GoogleGenerator(Generator):
    """Interface for Google Gemini models via the google-genai SDK.

    Uses the Gemini Developer API by default. Provide API key via `GOOGLE_API_KEY`.
    """

    generator_family_name = "Google"
    supports_multiple_generations = False

    # Environment variable for Gemini Developer API
    ENV_VAR = "GOOGLE_API_KEY"

    # Map to SDK's `max_output_tokens`, keep other defaults from base
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS

    def _load_client(self):
        if _import_error is not None or genai is None:
            raise ImportError(
                f"google-genai SDK is not available: {_import_error}. Install with `pip install google-genai`."
            )
        if not self.api_key:
            raise APIKeyMissingError(
                "Put the Gemini API key in the "
                f"{self.ENV_VAR} environment variable (this was empty)\n"
                f"e.g.: export {self.ENV_VAR}='AIza..." + "'"
            )
        self.client = genai.Client(api_key=self.api_key)

    def _clear_client(self):
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
        if self.name in ("", None):
            raise ValueError(
                f"{self.generator_family_name} requires model name to be set, e.g. --model_name gemini-2.0-flash-001"
            )

    def __init__(self, name="", config_root=None):
        if config_root is None:
            from garak import _config

            config_root = _config

        self.name = name
        self._load_config(config_root)
        self.fullname = f"{self.generator_family_name}:{self.name}"
        
        # Set context length from mapping if available
        if self.name in context_lengths:
            self.context_len = context_lengths[self.name]
        else:
            self.context_len = 1000000  # Default fallback for unknown models

        self._load_client()
        self._validate_config()

        super().__init__(self.name, config_root=config_root)

        # Clear client config to enable object to pickle
        self._clear_client()

    @backoff.on_exception(backoff.fibo, BACKOFF_EXCS, max_value=70)
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        if self.client is None:
            # reload client once when consuming the generator
            self._load_client()

        # Map garak params to google-genai config
        config: dict = {"max_output_tokens": getattr(self, "max_tokens", 150)}
        if hasattr(self, "temperature") and getattr(self, "temperature") is not None:
            config["temperature"] = getattr(self, "temperature")

        try:
            client = self.client
            if client is None:
                logging.error("Gemini client is not initialized")
                return [None]
            if genai_types is not None:
                cfg = genai_types.GenerateContentConfig(**config)
                response = client.models.generate_content(
                    model=self.name,
                    contents=prompt,
                    config=cfg,
                )
            else:
                response = client.models.generate_content(
                    model=self.name,
                    contents=prompt,
                )
            text = getattr(response, "text", None)
            if isinstance(text, str) and text != "":
                return [text]
            else:
                # Fallback: try to extract first candidate text if property missing
                try:
                    candidates = getattr(response, "candidates", None)
                    if candidates and hasattr(candidates[0], "content"):
                        parts = getattr(candidates[0].content, "parts", [])
                        for part in parts:
                            if hasattr(part, "text") and part.text:
                                return [part.text]
                except Exception:
                    pass
                logging.warning("No content in Gemini response")
                return [None]
        except Exception as e:
            logging.exception(f"Error calling Gemini API: {str(e)}")
            return [None] 