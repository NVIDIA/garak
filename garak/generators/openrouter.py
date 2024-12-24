"""OpenRouter.ai API Generator

Supports various LLMs through OpenRouter.ai's API. Put your API key in
the OPENROUTER_API_KEY environment variable. Put the name of the
model you want in either the --model_name command line parameter, or
pass it as an argument to the Generator constructor.

Usage:
    export OPENROUTER_API_KEY='your-api-key-here'
    garak --model_type openrouter --model_name MODEL_NAME

Example:
    garak --model_type openrouter --model_name anthropic/claude-3-opus

For available models, see: https://openrouter.ai/docs#models
"""

import logging
from typing import List, Union

from garak import _config
from garak.generators.openai import OpenAICompatible

# Default context lengths for common models
# These are just examples - any model from OpenRouter will work
context_lengths = {
    "openai/gpt-4-turbo-preview": 128000,
    "openai/gpt-3.5-turbo": 16385,
    "anthropic/claude-3-opus": 200000,
    "anthropic/claude-3-sonnet": 200000,
    "anthropic/claude-2.1": 200000,
    "google/gemini-pro": 32000,
    "meta/llama-2-70b-chat": 4096,
    "mistral/mistral-medium": 32000,
    "mistral/mistral-small": 32000
}

class OpenRouterGenerator(OpenAICompatible):
    """Generator wrapper for OpenRouter.ai models. Expects API key in the OPENROUTER_API_KEY environment variable"""

    ENV_VAR = "OPENROUTER_API_KEY"
    active = True
    generator_family_name = "OpenRouter"
    DEFAULT_PARAMS = {
        **{k: val for k, val in OpenAICompatible.DEFAULT_PARAMS.items() if k != "uri"},
        "max_tokens": 2000
    }

    def __init__(self, name="", config_root=_config):
        self.name = name
        self._load_config(config_root)
        if self.name in context_lengths:
            self.context_len = context_lengths[self.name]

        super().__init__(self.name, config_root=config_root)

    def _load_client(self):
        """Initialize the OpenAI client with OpenRouter.ai base URL"""
        import openai
        self.client = openai.OpenAI(
            api_key=self._get_api_key(),
            base_url="https://openrouter.ai/api/v1"
        )

        # Determine if we're using chat or completion based on model
        self.generator = self.client.chat.completions

    def _get_api_key(self):
        """Get API key from environment variable"""
        import os
        key = os.getenv(self.ENV_VAR)
        if not key:
            raise ValueError(f"Please set the {self.ENV_VAR} environment variable with your OpenRouter API key")
        return key

    def _validate_config(self):
        """Validate the configuration"""
        if not self.name:
            raise ValueError("Model name must be specified")

        # Set a default context length if not specified
        if self.name not in context_lengths:
            logging.info(
                f"Model {self.name} not in list of known context lengths. Using default of 4096 tokens."
            )
            self.context_len = 4096

    def _log_completion_details(self, prompt, response):
        """Log completion details at DEBUG level"""
        logging.debug("=== Model Input ===")
        if isinstance(prompt, str):
            logging.debug(f"Prompt: {prompt}")
        else:
            logging.debug("Messages:")
            for msg in prompt:
                logging.debug(f"- Role: {msg.get('role', 'unknown')}")
                logging.debug(f"  Content: {msg.get('content', '')}")

        logging.debug("\n=== Model Output ===")
        if hasattr(response, 'usage'):
            logging.debug(f"Prompt Tokens: {response.usage.prompt_tokens}")
            logging.debug(f"Completion Tokens: {response.usage.completion_tokens}")
            logging.debug(f"Total Tokens: {response.usage.total_tokens}")

        logging.debug("Generated Text:")
        if isinstance(response, list):
            for item in response:
                if hasattr(item, 'message'):
                    logging.debug(f"- {item.message.content}")
                elif hasattr(item, 'text'):
                    logging.debug(f"- {item.text}")
                else:
                    logging.debug(f"- {item}")
        else:
            for choice in response.choices:
                if hasattr(choice, 'message'):
                    logging.debug(f"- {choice.message.content}")
                else:
                    logging.debug(f"- {choice.text}")
        logging.debug("==================")

    def _call_model(self, prompt: Union[str, List[dict]], generations_this_call: int = 1):
        """Override _call_model to add logging"""
        try:
            response = super()._call_model(prompt, generations_this_call)
            # Get the raw response before it's processed
            raw_response = self.generator.create(
                model=self.name,
                messages=[{"role": "user", "content": prompt}] if isinstance(prompt, str) else prompt,
                n=generations_this_call if "n" not in self.suppressed_params else None,
                max_tokens=self.max_tokens if hasattr(self, 'max_tokens') else None
            )
            self._log_completion_details(prompt, raw_response)
            return response
        except Exception as e:
            logging.error(f"Error in model call: {str(e)}")
            return [None]

DEFAULT_CLASS = "OpenRouterGenerator"
