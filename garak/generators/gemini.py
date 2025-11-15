"""
Generator for Google's Gemini models using the Google Generative AI Python client.
"""

import os
import backoff
from typing import List, Union

from google import genai
from google.genai import types
from google.genai.errors import APIError

from garak.generators.base import Generator
import garak._config as _config
import sys


class GeminiGenerator(Generator):
    """
    Interface for Google's Gemini models using the Google Generative AI Python client.
    
    Authentication:
    - API key: Set the GOOGLE_API_KEY environment variable or pass api_key parameter
    - Application Default Credentials (ADC): The client will automatically attempt to use ADC 
      when no API key is provided. ADC can be set up in multiple ways:
      * Run 'gcloud auth application-default login' to authenticate with your Google account
      * Set GOOGLE_APPLICATION_CREDENTIALS environment variable pointing to a service account key file
      * When running on Google Cloud Platform, credentials are automatically available
    
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
        # Use lazy loading - don't load model immediately
        self.client = None
        self.model = None

    def _load_model(self):
        """Load the Gemini model.
        
        Validates that the model name is supported and configures the model with appropriate parameters.
        Different models may have different capabilities and parameter constraints.
        
        Authentication:
        - If an API key is provided via the GOOGLE_API_KEY environment variable or api_key parameter,
          it will be used for authentication with the Gemini Developer API.
        - If no API key is provided, check for Vertex AI configuration via environment variables:
          * GOOGLE_CLOUD_PROJECT: Your Google Cloud project ID
          * GOOGLE_CLOUD_LOCATION: Your Google Cloud location (e.g., us-central1)
        """
        # Validate that the model name is supported
        if not self.name:
            raise ValueError("Model name is required for GeminiGenerator")
        
        # If model name contains 'audio', set modality to accept audio input
        if "audio" in self.name.lower():
            self.modality = {"in": {"audio"}, "out": {"text"}}
            logging.info(f"Audio model detected: {self.name}. Modality set to accept audio input.")
        
        # Initialize the Google GenAI client
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            vertexai = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() == "true"
            project = os.getenv("GOOGLE_CLOUD_PROJECT")
            location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
            if vertexai and project:
                self.client = genai.Client(vertexai=True, project=project, location=location)
            else:
                # Use GOOGLE_API_KEY from environment if available
                env_api_key = os.getenv(self.ENV_VAR)
                self.client = genai.Client(api_key=env_api_key)
        
        # Get the model from the client
        self.model = self.client.models.get(model=self.name)

    def _validate_env_var(self):
        """Override the default API key validation to allow for ADC when no API key is provided.
        
        For GCP services, authentication can be done via:
        1. API key (via GOOGLE_API_KEY environment variable or api_key parameter)
        2. Application Default Credentials (ADC) when no API key is provided
        
        ADC can be set up using 'gcloud auth application-default login' or by setting
        GOOGLE_APPLICATION_CREDENTIALS to point to a service account key file.
        """
    def _clear_model(self):
        """Clear the model to avoid pickling issues."""
        self.model = None

    def __init__(self, name="", config_root=_config, api_key=None):
        """Initialize the Gemini generator."""
        # Initialize default parameters before calling super().__init__
        self.temperature = self.DEFAULT_PARAMS["temperature"]
        self.top_p = self.DEFAULT_PARAMS["top_p"]
        self.top_k = self.DEFAULT_PARAMS["top_k"]
        self.max_output_tokens = self.DEFAULT_PARAMS["max_output_tokens"]
        self.api_key = api_key
        super().__init__(name, config_root)
        # Defer model loading until actually needed
        self.client = None
        self.model = None

    def _call_model(self, prompt: str, generations_this_call: int = 1) -> List[Union[str, None]]:
        """Call the Gemini model with the given prompt.
        
        Args:
            prompt: The input text to send to the model
            generations_this_call: Number of responses to generate
            
        Returns:
            A list of response strings, or None for failed generations
        """
        import logging
        
        try:
            # Load model if not already loaded
            if self.client is None or self.model is None:
                self._load_model()
            
            # Use backoff-decorated helper method for the actual API call
            # This ensures that multiple generations are obtained in a single call
            # and backoff doesn't discard completed generations
            response = self._generate_content_with_backoff(prompt, generations_this_call)
            return self._process_response(response, generations_this_call)
        except Exception as e:
            # If all retries failed, return None values for all expected generations
            logging.error(f"All retries failed for {self.name}: {e}")
            return [None] * generations_this_call

    @backoff.on_exception(backoff.expo, APIError, max_tries=5)
    def _generate_content_with_backoff(self, prompt: str, generations_this_call: int):
        """Generate content with backoff retry logic.

        This method generates content using the Gemini model with backoff retry logic.
        It loads the model if not already loaded, creates a generation config, and generates content.

        Args:
            prompt (str): The input text to send to the model.
            generations_this_call (int): The number of responses to generate.

        Returns:
            The response object from the Gemini API.
        """
        # Load model if not already loaded
        if self.client is None or self.model is None:
            self._load_model()
        
        import logging
        
        # Create generation config with candidate count for multiple generations
        generation_config = types.GenerateContentConfig(
            temperature=self.temperature,
            top_p=self.top_p,
            top_k=self.top_k,
            max_output_tokens=self.max_output_tokens,
            candidate_count=generations_this_call
        )
        
        # Generate content with the model
        try:
            response = self.client.models.generate_content(
                model=self.name,
                contents=prompt,
                config=generation_config
            )
            return response
            raise e  # This will trigger backoff retry
        except Exception as e:
            logging.error(f"Unexpected error when calling {self.name}: {e}")
            raise e  # Re-raise to be handled by caller

    def _process_response(self, response, generations_this_call: int) -> List[Union[str, None]]:
        """Process the API response and extract text from candidates.
        
        Args:
            response: The response object from the Gemini API
            generations_this_call: Expected number of generations
            
        Returns:
            List of response strings or None for failed generations
        """
        import logging
        responses = []
        
        try:
            # Process candidates if available
            if hasattr(response, "candidates") and response.candidates:
                for candidate in response.candidates:
                    if (hasattr(candidate, "content") and 
                        hasattr(candidate.content, "parts") and 
                        candidate.content.parts):
                        # Extract text from the first part
                        text_content = candidate.content.parts[0].text if candidate.content.parts[0].text else None
                        responses.append(text_content)
                    else:
                        logging.warning(f"Empty candidate response from Gemini model {self.name}")
                        responses.append(None)
            elif hasattr(response, "text") and response.text:
                # Fallback for single response format
                responses.append(response.text)
            else:
                logging.warning(f"No valid response format from Gemini model {self.name}")
                responses.append(None)
                
        except Exception as e:
            logging.error(f"Error processing response from {self.name}: {e}")
            # Fill with None values for the expected number of generations
            responses = [None] * generations_this_call
        
        # Ensure we return the expected number of responses
        while len(responses) < generations_this_call:
            responses.append(None)
        
        return responses[:generations_this_call]


DEFAULT_CLASS = "GeminiGenerator"
