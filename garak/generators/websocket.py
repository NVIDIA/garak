"""WebSocket generator for real-time LLM communication

This module provides WebSocket-based connectivity for testing LLM services
that use real-time bidirectional communication protocols.
"""

import asyncio
import json
import ssl
import time
import base64
import logging
from typing import List, Union, Dict, Any
from urllib.parse import urlparse

import jsonpath_ng
from jsonpath_ng.exceptions import JsonPathParserError

from garak import _config
from garak.attempt import Message, Conversation
from garak.exception import BadGeneratorException, GarakException
from garak.generators.base import Generator

logger = logging.getLogger(__name__)


class WebSocketGenerator(Generator):
    """Generator for WebSocket-based LLM services

    This generator connects to LLM services that communicate via WebSocket protocol,
    handling authentication, template-based messaging, and JSON response extraction.

    Configuration parameters:
    - uri: WebSocket URL (ws:// or wss://)
    - name: Display name for the service
    - auth_type: Authentication method (none, basic, bearer, custom)
    - username: Basic authentication username
    - api_key: API key for bearer token auth or password for basic auth
    - req_template: String template with $INPUT and $KEY placeholders
    - req_template_json_object: JSON object template for structured messages
    - headers: Additional WebSocket headers
    - response_json: Whether responses are JSON formatted
    - response_json_field: Field to extract from JSON responses (supports JSONPath)
    - response_after_typing: Wait for typing indicator completion
    - typing_indicator: String that indicates typing status
    - request_timeout: Seconds to wait for response
    - connection_timeout: Seconds to wait for connection
    - max_response_length: Maximum response length
    - verify_ssl: SSL certificate verification
    """

    DEFAULT_PARAMS = {
        "uri": "wss://echo.websocket.org",
        "name": "WebSocket LLM",
        "auth_type": "none",  # none, basic, bearer, custom
        "username": None,
        "api_key": None,
        "conversation_id": None,
        "req_template": "$INPUT",
        "req_template_json_object": None,
        "headers": {},
        "response_json": False,
        "response_json_field": "text",
        "response_after_typing": True,
        "typing_indicator": "typing",
        "request_timeout": 20,
        "connection_timeout": 10,
        "max_response_length": 10000,
        "verify_ssl": True,
    }

    ENV_VAR = "WEBSOCKET_API_KEY"
    extra_dependency_names = ["websockets"]

    def __init__(self, uri=None, config_root=_config):
        # Set uri if explicitly provided (overrides default)
        if uri:
            self.uri = uri

        # Let Configurable class handle all the DEFAULT_PARAMS magic
        super().__init__("", config_root)

        # Now validate that required values are formatted correctly
        if not self.uri:
            raise ValueError("WebSocket uri is required")

        parsed = urlparse(self.uri)
        if parsed.scheme not in ["ws", "wss"]:
            raise ValueError("URI must use ws:// or wss:// scheme")

        # Extract URI security attribute
        self.secure = parsed.scheme == "wss"

        # Set up authentication
        self._setup_auth()

        # Current WebSocket connection
        self.websocket = None

        # Validate jsonpath if using JSON responses
        if self.response_json and self.response_json_field:
            try:
                self.json_expr = jsonpath_ng.parse(self.response_json_field)
            except JsonPathParserError as e:
                logger.critical(
                    "Couldn't parse response_json_field %s", self.response_json_field
                )
                raise e

        logger.info(f"WebSocket generator initialized for {self.uri}")

    def _validate_env_var(self):
        """Only validate API key if it's actually needed in templates or auth"""
        if self.auth_type != "none":
            return super()._validate_env_var()

        # Check if templates require API key
        key_required = False
        if "$KEY" in str(self.req_template):
            key_required = True
        if self.req_template_json_object and "$KEY" in str(
            self.req_template_json_object
        ):
            key_required = True
        if self.headers and any("$KEY" in str(v) for v in self.headers.values()):
            key_required = True

        if key_required:
            return super()._validate_env_var()

        # No API key validation needed
        return

    def _setup_auth(self):
        """Set up authentication headers and credentials"""
        self.auth_header = None

        # Set up authentication headers
        if self.auth_type == "basic" and self.username and self.api_key:
            credentials = base64.b64encode(
                f"{self.username}:{self.api_key}".encode()
            ).decode()
            self.auth_header = f"Basic {credentials}"
        elif self.auth_type == "bearer" and self.api_key:
            self.auth_header = f"Bearer {self.api_key}"

        # Add auth header to headers dict
        if self.auth_header:
            self.headers = self.headers or {}
            self.headers["Authorization"] = self.auth_header

    def _format_message(self, prompt: str) -> str:
        """Format message using template system similar to REST generator"""
        # Prepare replacements
        replacements = {
            "$INPUT": prompt,
            "$KEY": self.api_key or "",
            "$CONVERSATION_ID": self.conversation_id or "",
        }

        # Use JSON object template if provided
        if self.req_template_json_object:
            message_obj = self._apply_replacements(
                self.req_template_json_object, replacements
            )
            return json.dumps(message_obj)

        # Use string template
        message = self.req_template
        for placeholder, value in replacements.items():
            message = message.replace(placeholder, value)

        return message

    def _apply_replacements(self, obj: Any, replacements: Dict[str, str]) -> Any:
        """Recursively apply replacements to a data structure"""
        if isinstance(obj, str):
            for placeholder, value in replacements.items():
                obj = obj.replace(placeholder, value)
            return obj
        elif isinstance(obj, dict):
            return {
                k: self._apply_replacements(v, replacements) for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [self._apply_replacements(item, replacements) for item in obj]
        else:
            return obj

    def _extract_response_text(self, response: str) -> str:
        """Extract text from response using jsonpath_ng for JSON field extraction"""
        if not self.response_json:
            return response

        try:
            response_data = json.loads(response)

            if self.response_json_field[0] != "$":
                # Direct field access
                if isinstance(response_data, list):
                    extracted = [item[self.response_json_field] for item in response_data]
                    return str(extracted[0]) if len(extracted) == 1 else str(extracted)
                else:
                    return str(response_data.get(self.response_json_field, response))
            else:
                # Use JSONPath via jsonpath_ng
                field_path_expr = jsonpath_ng.parse(self.response_json_field)
                responses = field_path_expr.find(response_data)
                if len(responses) == 1:
                    return str(responses[0].value)
                elif len(responses) > 1:
                    return str(responses[0].value)
                else:
                    logger.warning(
                        "JSONPath '%s' yielded no results, returning raw response",
                        self.response_json_field,
                    )
                    return response

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(
                "Failed to extract JSON field '%s': %s, returning raw response",
                self.response_json_field,
                e,
            )
            return response

    async def _connect_websocket(self):
        """Establish WebSocket connection with proper error handling"""
        try:
            # Prepare connection arguments
            connect_args = {
                "open_timeout": self.connection_timeout,
                "close_timeout": self.connection_timeout,
            }

            # Add headers if provided
            if self.headers:
                connect_args["additional_headers"] = self.headers

            # SSL verification
            if self.secure and not self.verify_ssl:
                connect_args["ssl"] = ssl.create_default_context()
                connect_args["ssl"].check_hostname = False
                connect_args["ssl"].verify_mode = ssl.CERT_NONE

            logger.debug(f"Connecting to WebSocket: {self.uri}")
            self.websocket = await self.websockets.connect(self.uri, **connect_args)
            logger.info(f"WebSocket connected to {self.uri}")

        except self.websockets.exceptions.InvalidURI as e:
            msg = f"Invalid WebSocket URI {self.uri}: {e}"
            logger.error(msg)
            raise BadGeneratorException(msg) from e
        except self.websockets.exceptions.InvalidHandshake as e:
            msg = f"WebSocket handshake failed for {self.uri}: {e}"
            logger.error(msg)
            raise BadGeneratorException(msg) from e
        except ssl.SSLError as e:
            msg = f"SSL error connecting to {self.uri}: {e}"
            logger.error(msg)
            raise BadGeneratorException(msg) from e
        except OSError as e:
            msg = f"Network error connecting to WebSocket {self.uri}: {e}"
            logger.error(msg)
            raise ConnectionError(msg) from e
        except asyncio.TimeoutError as e:
            msg = f"Connection timeout to WebSocket {self.uri}"
            logger.error(msg)
            raise ConnectionError(msg) from e

    async def _send_and_receive(self, message: str) -> str:
        """Send message and receive response with timeout and typing indicator handling"""
        if not self.websocket:
            await self._connect_websocket()

        try:
            # Send message
            await self.websocket.send(message)
            logger.debug("WebSocket message sent")

            # Collect response parts
            response_parts = []
            start_time = time.time()
            typing_detected = False

            while time.time() - start_time < self.request_timeout:
                try:
                    # Wait for message with timeout
                    remaining_time = self.request_timeout - (time.time() - start_time)
                    if remaining_time <= 0:
                        break

                    response = await asyncio.wait_for(
                        self.websocket.recv(), timeout=min(2.0, remaining_time)
                    )

                    logger.debug("WebSocket message received")

                    # Handle typing indicators
                    if self.response_after_typing and self.typing_indicator in response:
                        typing_detected = True
                        continue

                    # If we were waiting for typing to finish and got a non-typing message
                    if typing_detected and self.typing_indicator not in response:
                        response_parts.append(response)
                        break

                    # Collect response parts
                    response_parts.append(response)

                    # If not using typing indicators, assume first response is complete
                    if not self.response_after_typing:
                        break

                    # Check if we have enough content
                    total_length = sum(len(part) for part in response_parts)
                    if total_length > self.max_response_length:
                        logger.debug("Max response length reached")
                        break

                except asyncio.TimeoutError:
                    logger.debug("WebSocket receive timeout")
                    # If we have some response, break; otherwise continue waiting
                    if response_parts:
                        break
                    continue
                except self.websockets.exceptions.ConnectionClosed:
                    logger.warning("WebSocket connection closed during receive")
                    break

            # Combine response parts
            full_response = "".join(response_parts)
            logger.debug(f"WebSocket response received ({len(full_response)} chars)")

            return full_response

        except OSError as e:
            logger.error(f"Network error in WebSocket communication: {e}")
            if self.websocket:
                await self.websocket.close()
                self.websocket = None
            raise ConnectionError(f"WebSocket network error: {e}") from e

    async def _generate_async(self, prompt: str) -> str:
        """Async wrapper for generation"""
        formatted_message = self._format_message(prompt)
        raw_response = await self._send_and_receive(formatted_message)
        return self._extract_response_text(raw_response)

    def _has_system_prompt(self, prompt: Conversation) -> bool:
        """Check if conversation contains system prompts"""
        if hasattr(prompt, "turns") and prompt.turns:
            for turn in prompt.turns:
                if hasattr(turn, "role") and turn.role == "system":
                    return True
        return False

    def _has_single_turn(self, prompt: Conversation) -> bool:
        """Check if conversation has only one turn"""
        return len(prompt.turns) == 1

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1, **kwargs
    ) -> List[Union[Message, None]]:
        """Call the WebSocket LLM model with smart limitation detection"""
        try:
            # Check for unsupported features and skip gracefully
            if self._has_system_prompt(prompt):
                logger.warning(
                    "WebSocket generator doesn't support system prompts yet - skipping test"
                )
                return [None]

            if not self._has_single_turn(prompt):
                logger.warning(
                    "WebSocket generator doesn't support conversation history yet - skipping test"
                )
                return [None]

            # Extract text from simple, single-turn conversation
            prompt_text = prompt.last_message().text

            # Run async generation in event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                response_text = loop.run_until_complete(
                    self._generate_async(prompt_text)
                )
                # Create Message objects for garak
                if response_text:
                    message = Message(text=response_text)
                    return [message]
                else:
                    message = Message(text=None)
                    return [message]
            finally:
                loop.close()

        except (ConnectionError, BadGeneratorException) as e:
            logger.error(f"WebSocket generation failed: {e}")
            return [Message(text="")]
        except GarakException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in WebSocket generation: {e}")
            return [Message(text="")]

    def __del__(self):
        """Clean up WebSocket connection"""
        if hasattr(self, "websocket") and self.websocket:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.websocket.close())
                loop.close()
            except Exception as e:
                logger.warning("websocket teardown error", exc_info=e)


DEFAULT_CLASS = "WebSocketGenerator"
