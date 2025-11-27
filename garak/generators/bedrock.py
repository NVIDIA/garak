"""AWS Bedrock generator

Supports foundation models available through AWS Bedrock using standard AWS authentication.

To get started with this generator:

#. Visit https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html
   to see available models
#. Set up AWS credentials: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html or a Bedrock API Key
#. Run garak with --target_type bedrock and --target_name <model-id>

"""

import logging
import os
import re
from typing import List, Union

import backoff

from garak import _config
from garak.attempt import Message, Conversation
import garak.exception
from garak.generators.base import Generator

MODEL_ALIASES = {
    "claude-4-5-haiku": "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "claude-4-5-sonnet": "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "claude-4-1-opus": "us.anthropic.claude-opus-4-1-20250805-v1:0",  # US Inference Endpoint
    "claude-4-opus": "us.anthropic.claude-opus-4-20250514-v1:0",  # US Inference Endpoint
    "claude-4-sonnet": "global.anthropic.claude-sonnet-4-20250514-v1:0",
    "nova-premier": "us.amazon.nova-premier-v1:0",  # US Inference Endpoint
    "nova-pro": "us.amazon.nova-pro-v1:0",  # US Inference Endpoint
    "nova-lite": "us.amazon.nova-lite-v1:0",  # US Inference Endpoint
    "nova-micro": "us.amazon.nova-micro-v1:0",  # US Inference Endpoint
}


class BedrockGenerator(Generator):
    """Interface for AWS Bedrock foundation models using Converse API"""

    active = True
    generator_family_name = "Bedrock"
    supports_multiple_generations = False
    extra_dependency_names = ["boto3", "botocore"]

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.7,
        "top_p": 1.0,
        "stop": [],
        "region": "us-east-1",
    }

    def __init__(self, name="", config_root=_config):
        """Initialize the Bedrock generator.

        Args:
            name: Model name or alias (e.g., "claude-3-sonnet" or full model ID)
            config_root: Configuration root object
        """
        self.name = name
        self._load_config(config_root)

        if self.name in MODEL_ALIASES:
            resolved_name = MODEL_ALIASES[self.name]
            logging.info(f"Resolved model alias '{self.name}' to: {resolved_name}")
            self.name = resolved_name

        # Validate model ID format
        if self.name:
            # Check if model is in our known aliases (already resolved)
            if self.name in MODEL_ALIASES.values():
                # Valid known model
                pass
            # Check if it's an ARN format
            elif self.name.startswith("arn:aws:bedrock:"):
                arn_pattern = r"^arn:aws:bedrock:[a-z0-9-]+:[0-9]+:inference-profile/[a-z0-9.:-]+$"
                if not re.match(arn_pattern, self.name):
                    raise ValueError(
                        f"Model ID '{self.name}' appears to be an ARN but is not in the correct format. "
                        f"Expected format: 'arn:aws:bedrock:region:account:inference-profile/model-id'"
                    )
            # Check if it matches standard Bedrock model ID format (must have provider.model structure)
            elif "." in self.name:
                # Standard model IDs should have format: provider.model-name or region.provider.model-name
                bedrock_id_pattern = r"^([a-z0-9-]+\.)+[a-z0-9.:-]+$"
                if not re.match(bedrock_id_pattern, self.name):
                    raise ValueError(
                        f"Model ID '{self.name}' does not appear to be a valid Bedrock model ID format. "
                        f"Expected format examples:\n"
                        f"  - Model ID: 'anthropic.claude-v2' or 'us.amazon.nova-pro-v1:0'\n"
                        f"  - Inference profile: 'us.anthropic.claude-4-1-sonnet-v2:0'\n"
                        f"  - ARN: 'arn:aws:bedrock:region:account:inference-profile/model-id'"
                    )
            else:
                # No dots and not an ARN
                supported_aliases = ", ".join(sorted(MODEL_ALIASES.keys()))
                raise ValueError(
                    f"Model ID '{self.name}' is not in the list of supported Bedrock models. "
                    f"Please use one of the known aliases: {supported_aliases}\n"
                    f"Or provide a full Bedrock model ID (e.g., 'anthropic.claude-v2' or 'us.amazon.nova-pro-v1:0')"
                )

        super().__init__(self.name, config_root=config_root)
        self._validate_env_var()
        self._load_client()

    def _validate_env_var(self):
        """Validate and set region from environment variables if not configured.

        Checks AWS_REGION and AWS_DEFAULT_REGION environment variables only if
        the region parameter is still at its default value.
        """
        if self.region == "us-east-1":
            env_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
            if env_region:
                logging.info(f"Using AWS region from environment: {env_region}")
                self.region = env_region

        return super()._validate_env_var()

    def _load_client(self):
        """Load and configure the boto3 bedrock-runtime client.

        Uses boto3's standard credential chain for authentication.
        """

        self.client = self.boto3.client(
            service_name="bedrock-runtime",
            region_name=self.region,
        )

        logging.info(f"Loaded boto3 bedrock-runtime client for region {self.region}")

    def _clear_client(self):
        """Clear the boto3 client to enable object pickling."""
        if hasattr(self, "client"):
            self.client = None
        for module_name in self.extra_dependency_names:
            setattr(self, module_name, None)

    def __getstate__(self):
        """Prepare object for pickling by clearing the boto3 client."""
        self._clear_client()
        return self.__dict__

    def __setstate__(self, state):
        """Restore object from pickle and reload the boto3 client."""
        self.__dict__.update(state)
        self._load_client()

    @staticmethod
    def _conversation_to_list(conversation: Conversation) -> list[dict]:
        """Convert Conversation object to Bedrock Converse API message format.

        AWS Bedrock expects messages in the format:
        {"role": "user", "content": [{"text": "message text"}]}

        Args:
            conversation: Conversation object to convert

        Returns:
            List of message dictionaries in Bedrock format
        """
        turn_list = [
            {"role": turn.role, "content": [{"text": turn.content.text}]}
            for turn in conversation.turns
        ]
        return turn_list

    @backoff.on_exception(
        backoff.fibo,
        garak.exception.GeneratorBackoffTrigger,
        max_value=70,
    )
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """Call the Bedrock model using the Converse API.

        Args:
            prompt: Conversation object containing the prompt turns
            generations_this_call: Number of generations to request (currently only 1 is supported)

        Returns:
            List of Message objects containing the generated text, or [None] on error
        """
        if self.client is None:
            self._load_client()

        messages = self._conversation_to_list(prompt)

        if not messages:
            logging.error("No valid messages to send to Bedrock")
            return [None]

        inference_config = {}
        if self.temperature is not None:
            inference_config["temperature"] = float(self.temperature)
        if hasattr(self, "max_tokens") and self.max_tokens is not None:
            inference_config["maxTokens"] = int(self.max_tokens)
        if self.top_p is not None:
            inference_config["topP"] = float(self.top_p)
        if self.stop:
            inference_config["stopSequences"] = self.stop

        call_args = {
            "modelId": self.name,
            "messages": messages,
        }
        if inference_config:
            call_args["inferenceConfig"] = inference_config

        try:
            response = self.client.converse(**call_args)

            if not response or "output" not in response:
                logging.error("Malformed response from Bedrock: missing 'output' field")
                return [None]

            if "message" not in response["output"]:
                logging.error(
                    "Malformed response from Bedrock: missing 'message' in output"
                )
                return [None]

            message = response["output"]["message"]
            if "content" not in message or not message["content"]:
                logging.error(
                    "Malformed response from Bedrock: missing or empty 'content' in message"
                )
                return [None]

            content_block = message["content"][0]
            if "text" not in content_block:
                logging.error(
                    "Malformed response from Bedrock: missing 'text' in content block"
                )
                return [None]

            text = content_block["text"]
            return [Message(text=text)]

        except Exception as e:

            if isinstance(e, self.botocore.exceptions.ClientError):
                error_code = e.response.get("Error", {}).get("Code", "")
                error_message = e.response.get("Error", {}).get("Message", "")

                logging.error(f"Bedrock API error [{error_code}]: {error_message}")

                if error_code in ["ThrottlingException", "ServiceUnavailableException"]:
                    raise garak.exception.GeneratorBackoffTrigger from e

                return [None]

            logging.exception("Error calling Bedrock model")
            return [None]


DEFAULT_CLASS = "BedrockGenerator"
