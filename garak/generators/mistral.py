""" Support `Mistral <https://mistral.ai>`_ hosted endpoints  """

import backoff
import json
import logging
import requests
from typing import List
from mistralai import Mistral, models

from garak import _config
from garak.generators.base import Generator
from garak.attempt import Message, Conversation


class MistralGenerator(Generator):
    """Interface for public endpoints of models hosted in Mistral La Plateforme (console.mistral.ai).
    Expects API key in MISTRAL_API_TOKEN environment variable.
    """

    generator_family_name = "mistral"
    fullname = "Mistral AI"
    supports_multiple_generations = False
    ENV_VAR = "MISTRAL_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "name": "mistral-large-latest",
        # Sampling parameters
        "top_p": None,                    # Nucleus sampling (0.0-1.0)
        "frequency_penalty": None,        # Penalize word repetition by frequency (0.0-2.0)
        "presence_penalty": None,         # Penalize word repetition (0.0-2.0)
        # Generation control
        "n": None,                        # Number of completions to return
        "stop": None,                     # Stop sequences (string or list)
        "stream": False,                  # Whether to stream responses
        # Response format
        "response_format": None,          # Output format (text, json_object, json_schema)
        # Tool/function calling
        "tools": None,                    # List of available tools/functions
        "tool_choice": None,              # Tool calling control (none, auto, any, required)
        "parallel_tool_calls": None,      # Enable parallel function calling
        # Safety and prompting
        "safe_prompt": None,              # Inject safety prompt
        "prompt_mode": None,              # Toggle reasoning mode
        # Optimization
        "prediction": None,               # Expected completion for optimization
    }

    # Parameter mapping for API calls (same for both SDK and raw HTTP)
    _PARAM_MAPPING = {
        "max_tokens": "max_tokens",
        "temperature": "temperature", 
        "seed": "random_seed",  # Both SDK and raw API use 'random_seed'
        "top_p": "top_p",
        "frequency_penalty": "frequency_penalty",
        "presence_penalty": "presence_penalty",
        "n": "n",
        "stop": "stop",
        "stream": "stream",
        "response_format": "response_format",
        "tools": "tools",
        "tool_choice": "tool_choice",
        "parallel_tool_calls": "parallel_tool_calls",
        "safe_prompt": "safe_prompt",
        "prompt_mode": "prompt_mode",
        "prediction": "prediction",
    }

    # avoid attempt to pickle the client attribute
    def __getstate__(self) -> object:
        self._clear_client()
        return dict(self.__dict__)

    # restore the client attribute
    def __setstate__(self, d) -> object:
        self.__dict__.update(d)
        self._load_client()

    def _load_client(self):
        self.client = Mistral(api_key=self.api_key)

    def _clear_client(self):
        self.client = None

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)
        self._load_client()

    @backoff.on_exception(backoff.fibo, models.SDKError, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call=1
    ) -> List[Message | None]:
        messages = self._conversation_to_list(prompt)
        
        try:
            logging.debug(f"Making Mistral API call with model: {self.name}")
            # Build API parameters, excluding None values
            api_params = {
                "model": self.name,
                "messages": messages,
            }
            
            # Add all non-None parameters using dictionary comprehension
            api_params.update({
                api_param: getattr(self, attr_name)
                for attr_name, api_param in self._PARAM_MAPPING.items()
                if getattr(self, attr_name, None) is not None
            })
            
            # Handle special case: top_k fallback to top_p
            if self.top_k is not None and self.top_p is None:
                api_params["top_p"] = self.top_k
                
            chat_response = self.client.chat.complete(**api_params)
            logging.debug(f"Mistral API call successful, processing response")
            
            # Handle both string content and list of chunks (with thinking sequences)
            content = chat_response.choices[0].message.content
            if isinstance(content, list):
                logging.debug(f"Mistral returned chunked content with {len(content)} chunks")
                # Extract text chunks and filter out thinking chunks
                text_parts = []
                for chunk in content:
                    if isinstance(chunk, dict):
                        chunk_type = chunk.get('type', 'unknown')
                        if chunk_type == 'text':
                            text_parts.append(chunk.get('text', ''))
                        elif chunk_type == 'thinking':
                            logging.debug(f"Filtered out thinking chunk: {chunk.get('thinking', '')[:100]}...")
                        else:
                            logging.warning(f"Unknown chunk type: {chunk_type}")
                content = ''.join(text_parts)
                logging.debug(f"Final extracted content length: {len(content)}")
            
            return [Message(content)]
            
        except Exception as e:
            # If we get a Pydantic validation error, try to make a raw HTTP request
            error_str = str(e).lower()
            error_type = type(e).__name__.lower()
            
            # Log the error details for debugging
            logging.debug(f"Exception caught: {type(e).__name__}")
            logging.debug(f"Error string (first 500 chars): {str(e)[:500]}")
            
            # Check for various Pydantic/validation error indicators
            validation_keywords = [
                "validation error", "unmarshaller", "pydantic", "input should be",
                "validationerror", "union_tag_invalid", "string_type", "model_type",
                "tagged-union", "thinking", "imageurlchunk", "documenturlchunk", 
                "textchunk", "referencechunk", "nullable"
            ]
            
            # Check if it's a Pydantic ValidationError by type or content
            is_pydantic_validation_error = (
                "ValidationError" in type(e).__name__ or
                "pydantic" in str(type(e)).lower() or
                hasattr(e, 'error_count')  # Pydantic ValidationError has this attribute
            )
            
            is_validation_error = (
                is_pydantic_validation_error or
                any(keyword in error_str for keyword in validation_keywords) or
                any(keyword in error_type for keyword in ["validation", "pydantic"]) or
                "thinking" in error_str or
                "choices.0.message.content" in error_str  # Specific to this error pattern
            )
            
            logging.info(f"Error type: {type(e).__name__}, Is validation error: {is_validation_error}")
            
            if is_validation_error:
                logging.warning(f"Pydantic validation error detected, attempting raw HTTP request: {type(e).__name__}")
                logging.debug(f"Full error: {str(e)}")
                try:
                    return self._call_model_raw(messages)
                except Exception as raw_e:
                    raw_error_str = str(raw_e).lower()
                    # If raw HTTP failed due to server issues (5xx), re-raise that error for backoff retry
                    if any(code in raw_error_str for code in ["503", "502", "504", "500"]):
                        logging.error(f"Raw HTTP request failed with server error, will retry: {raw_e}")
                        raise raw_e  # Let backoff handle server errors
                    else:
                        logging.error(f"Raw HTTP request failed with client error: {raw_e}")
                        # For client errors, raise the original validation error
                        raise e
            else:
                logging.error(f"Non-validation error, re-raising: {type(e).__name__}: {e}")
                raise e

    @backoff.on_exception(
        backoff.fibo, 
        requests.exceptions.HTTPError, 
        max_value=70,
        giveup=lambda e: e.response.status_code < 500 if hasattr(e, 'response') and e.response else False
    )
    def _call_model_raw(self, messages):
        """Fallback method using raw HTTP requests to bypass Pydantic validation"""
        url = "https://api.mistral.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        # Build payload, excluding None values
        payload = {
            "model": self.name,
            "messages": messages
        }
        
        # Add all non-None parameters using dictionary comprehension
        payload.update({
            api_param: getattr(self, attr_name)
            for attr_name, api_param in self._PARAM_MAPPING.items()
            if getattr(self, attr_name, None) is not None
        })
        
        # Handle special case: top_k fallback to top_p
        if self.top_k is not None and self.top_p is None:
            payload["top_p"] = self.top_k
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            # Parse JSON manually to avoid any Pydantic issues
            data = json.loads(response.text)
            logging.debug(f"Raw HTTP response received: {type(data)}")
            
            content = data["choices"][0]["message"]["content"]
            logging.debug(f"Raw content type: {type(content)}, content preview: {str(content)[:200]}")
            
            # Handle chunked content with thinking sequences
            if isinstance(content, list):
                logging.debug(f"Raw request: Mistral returned chunked content with {len(content)} chunks")
                text_parts = []
                for i, chunk in enumerate(content):
                    logging.debug(f"Processing chunk {i}: {type(chunk)} - {str(chunk)[:100]}")
                    if isinstance(chunk, dict):
                        chunk_type = chunk.get('type', 'unknown')
                        if chunk_type == 'text':
                            text_content = chunk.get('text', '')
                            text_parts.append(text_content)
                            logging.debug(f"Added text chunk: {len(text_content)} chars")
                        elif chunk_type == 'thinking':
                            thinking_content = chunk.get('thinking', '')
                            logging.debug(f"Filtered out thinking chunk: {len(thinking_content)} chars - {thinking_content[:100]}...")
                        else:
                            logging.warning(f"Raw request: Unknown chunk type: {chunk_type}")
                content = ''.join(text_parts)
                logging.debug(f"Raw request: Final extracted content length: {len(content)}")
            
            return [Message(content)]
            
        except Exception as e:
            logging.error(f"Raw HTTP request failed: {e}")
            logging.error(f"Response status: {response.status_code if 'response' in locals() else 'No response'}")
            logging.error(f"Response text: {response.text[:500] if 'response' in locals() else 'No response'}")
            raise e


DEFAULT_CLASS = "MistralGenerator"
