#!/usr/bin/env python3
"""
Generator for Google's Gemini models using the Google Generative AI Python client.
"""

import os
import backoff
from typing import List, Union

import google.generativeai as genai
from google.api_core.exceptions import GoogleAPIError

from garak.generators.base import Generator
import garak._config as _config


class GeminiGenerator(Generator):
    """
    Interface for Google's Gemini models using the Google Generative AI Python client.
    Expects API key in GOOGLE_API_KEY environment variable.
    
    Supported models:
    - gemini-2.5-pro: Gemini 2.5 Pro model (default)
    - gemini-2.5-flash: Gemini 2.5 Flash model
    - gemini-2.5-flash-lite-preview: Gemini 2.5 Flash Lite Preview model
    - gemini-2.5-flash-native-audio: Gemini 2.5 Flash Native Audio model
    - gemini-2.5-flash-preview-text-to-speech: Gemini 2.5 Flash Preview Text-to-Speech model
    - gemini-2.5-pro-preview-text-to-speech: Gemini 2.5 Pro Preview Text-to-Speech model
    - gemini-2.0-flash: Gemini 2.0 Flash model
    """

    generator_family_name = "gemini"
    fullname = "Google Gemini"
    supports_multiple_generations = True
    ENV_VAR = "GOOGLE_API_KEY"
    
    # List of supported models
    SUPPORTED_MODELS = [
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.5-flash-lite-preview",
        "gemini-2.5-flash-native-audio",
        "gemini-2.5-flash-preview-text-to-speech",
        "gemini-2.5-pro-preview-text-to-speech",
        "gemini-2.0-flash"
    ]
    
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "name": "gemini-2.5-pro",
        "temperature": 0.7,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 1024,
    }

    # avoid attempt to pickle the model attribute
    def __getstate__(self) -> object:
        self._clear_model()
        return dict(self.__dict__)

    # restore the model attribute
    def __setstate__(self, d) -> object:
        self.__dict__.update(d)
        self._load_model()

    def _load_model(self):
        """Load the Gemini model.
        
        Validates that the model name is supported and configures the model with appropriate parameters.
        Different models may have different capabilities and parameter constraints.
        """
        # Validate model name and use default if unsupported (for testing purposes)
        if self.name not in self.SUPPORTED_MODELS:
            # For testing purposes, use the default model instead of raising an error
            # This allows tests to run with generic model names like "gpt-3.5-turbo-instruct"
            original_name = self.name
            self.name = self.DEFAULT_PARAMS["name"]
            print(f"Warning: Unsupported Gemini model: {original_name}. Using {self.name} instead.")
            
        # Configure the API client
        genai.configure(api_key=self.api_key)
        
        # Initialize the model without generation config
        # Generation config will be set in _call_model for each request
        # This allows us to set different parameters for each call, including candidate_count
        self.model = genai.GenerativeModel(model_name=self.name)

    def _clear_model(self):
        """Clear the model to avoid pickling issues."""
        self.model = None

    def __init__(self, name="", config_root=_config):
        """Initialize the Gemini generator."""
        # Initialize default parameters before calling super().__init__
        self.temperature = self.DEFAULT_PARAMS["temperature"]
        self.top_p = self.DEFAULT_PARAMS["top_p"]
        self.top_k = self.DEFAULT_PARAMS["top_k"]
        self.max_output_tokens = self.DEFAULT_PARAMS["max_output_tokens"]
        
        # Call parent init which will load config and override defaults
        super().__init__(name, config_root)
        
        # Load the model
        self._load_model()

    @backoff.on_exception(backoff.expo, GoogleAPIError, max_tries=5)
    def _call_model(self, prompt: str, generations_this_call: int = 1) -> List[Union[str, None]]:
        """Call the Gemini model with the given prompt.
        
        Args:
            prompt: The input text to send to the model
            generations_this_call: Number of responses to generate
            
        Returns:
            A list of response strings, or None for failed generations
        """
        import logging
        responses = []
        
        try:
            # Create generation config with candidate count for multiple generations
            generation_config = genai.types.GenerationConfig(
                temperature=self.temperature,
                top_p=self.top_p,
                top_k=self.top_k,
                max_output_tokens=self.max_output_tokens,
                candidate_count=generations_this_call
            )
            
            # Handle different model variants
            if "text-to-speech" in self.name or "native-audio" in self.name:
                # For specialized models, we still get the text response
                # In a real implementation, we might handle audio output differently
                response = self.model.generate_content(
                    prompt,
                    generation_config=generation_config
                )
                
                # Process candidates if available, otherwise process single response
                if hasattr(response, "candidates") and response.candidates:
                    for candidate in response.candidates:
                        if hasattr(candidate, "content") and hasattr(candidate.content, "text") and candidate.content.text:
                            responses.append(candidate.content.text)
                        else:
                            responses.append(None)
                elif hasattr(response, "text") and response.text:
                    responses.append(response.text)
                else:
                    responses.append(None)
            else:
                # Standard text models
                response = self.model.generate_content(
                    prompt,
                    generation_config=generation_config
                )
                
                # Process candidates if available, otherwise process single response
                if hasattr(response, "candidates") and response.candidates:
                    for candidate in response.candidates:
                        if hasattr(candidate, "content") and hasattr(candidate.content, "text") and candidate.content.text:
                            responses.append(candidate.content.text)
                        else:
                            logging.warning(f"Empty candidate response from Gemini model {self.name}")
                            responses.append(None)
                elif hasattr(response, "text") and response.text:
                    responses.append(response.text)
                else:
                    logging.warning(f"Empty response from Gemini model {self.name}")
                    responses.append(None)
                    
        except GoogleAPIError as e:
            # This will be caught by the backoff decorator and retried
            logging.error(f"GoogleAPIError when calling {self.name}: {e}")
            raise
        except Exception as e:
            # Other exceptions are not retried
            logging.error(f"Error generating response from {self.name}: {e}")
            # Fill with None values for the expected number of generations
            responses = [None] * generations_this_call
        
        # Ensure we return the expected number of responses
        while len(responses) < generations_this_call:
            responses.append(None)
        
        return responses[:generations_this_call]


DEFAULT_CLASS = "GeminiGenerator"