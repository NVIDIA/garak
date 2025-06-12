"""Cohere AI model support

Support for Cohere's text generation API. Uses the command model by default,
but just supply the name of another either on the command line or as the
constructor param if you want to use that. You'll need to set an environment
variable called COHERE_API_KEY to your Cohere API key, for this generator.

NOTE: As of Cohere v5.15.0, the generate API is legacy and chat API is recommended.
This implementation supports both methods, with generate used as the default
for backwards compatibility.
"""

import logging
from typing import List, Union

import backoff
from cohere.core.api_error import ApiError
import cohere
import tqdm

from garak.generators.base import Generator
import garak._config as _config


COHERE_GENERATION_LIMIT = (
    5  # c.f. https://docs.cohere.com/reference/generate 18 may 2023
)


class CohereGenerator(Generator):
    """Interface to Cohere's python library for their text2text model.

    Expects API key in COHERE_API_KEY environment variable.
    Uses generate API by default (legacy in v5+) but can use chat API if use_chat=True.
    """

    ENV_VAR = "COHERE_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.750,
        "k": 0,
        "p": 0.75,
        "preset": None,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0,
        "stop": [],
        "use_chat": True,  # Whether to use chat API (recommended in v5+) or generate API (legacy)
    }

    supports_multiple_generations = True
    generator_family_name = "Cohere"

    def __init__(self, name="command", config_root=_config):
        self.name = name
        self.fullname = f"Cohere {self.name}"

        super().__init__(self.name, config_root=config_root)

        logging.debug(
            "Cohere generation request limit capped at %s", COHERE_GENERATION_LIMIT
        )
        self.generator = cohere.ClientV2(api_key=self.api_key)
        self.use_chat = self.use_chat  # Get from DEFAULT_PARAMS

    @backoff.on_exception(backoff.fibo, ApiError, max_value=70)
    def _call_cohere_api(self, prompt, request_size=COHERE_GENERATION_LIMIT):
        """Empty prompts raise API errors (e.g. invalid request: prompt must be at least 1 token long).
        We catch these using the ApiError base class in Cohere v5+.
        Filtering exceptions based on message instead of type, in backoff, isn't immediately obvious
        - on the other hand blank prompt / RTP shouldn't hang forever
        """
        if prompt == "":
            return [""] * request_size
        else:
            if self.use_chat:
                # Use chat API (recommended in v5+)
                responses = []
                # Chat API doesn't support num_generations, so we need to make multiple calls
                for _ in range(request_size):
                    try:
                        # Use the correct UserChatMessageV2 class as confirmed by testing
                        message = cohere.UserChatMessageV2(content=prompt)
                        
                        response = self.generator.chat(
                            model=self.name,
                            messages=[message],
                            temperature=self.temperature,
                            max_tokens=self.max_tokens,
                            k=self.k,
                            p=self.p,
                            frequency_penalty=self.frequency_penalty,
                            presence_penalty=self.presence_penalty,
                        )
                        
                        # Extract text from message content (confirmed structure from testing)
                        if hasattr(response, 'message') and hasattr(response.message, 'content'):
                            # Get the first text content item
                            for content_item in response.message.content:
                                if hasattr(content_item, 'text'):
                                    responses.append(content_item.text)
                                    break
                            else:
                                # No text content found
                                logging.warning("No text content found in chat response")
                                responses.append(str(response))
                        else:
                            logging.warning("Chat response structure doesn't match expected format")
                            responses.append(str(response))
                    except Exception as e:
                        logging.error(f"Chat API error: {e}")
                        responses.append(f"Error: Could not process Cohere chat response: {str(e)}[:100]...")
                        
                # Ensure we return the correct number of responses
                if len(responses) < request_size:
                    responses.extend(["Error: Failed to generate response"] * (request_size - len(responses)))
                return responses
            else:
                # Use generate API (legacy in v5+)
                response = self.generator.generate(
                    model=self.name,
                    prompt=prompt,
                    temperature=self.temperature,
                    num_generations=request_size,
                    max_tokens=self.max_tokens,
                    preset=self.preset,
                    k=self.k,
                    p=self.p,
                    frequency_penalty=self.frequency_penalty,
                    presence_penalty=self.presence_penalty,
                    end_sequences=self.stop,
                )
                # In v5+, the response format has changed - generations is a list of tuples
                if hasattr(response, 'generations'):
                    # Handle the v5+ API response format
                    return [gen.text for gen in response.generations]
                else:
                    # Try to handle other possible response formats
                    try:
                        if isinstance(response, list):
                            return [g.text for g in response]
                        elif hasattr(response, 'text'):
                            return [response.text]
                        else:
                            # Last resort - try to convert response to string
                            return [str(response)]
                    except Exception as e:
                        logging.error(f"Failed to extract text from Cohere response: {e}")
                        return ["Error: Could not process Cohere response"] * request_size

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Cohere's _call_model does sub-batching before calling,
        and so manages chunking internally"""
        quotient, remainder = divmod(generations_this_call, COHERE_GENERATION_LIMIT)
        request_sizes = [COHERE_GENERATION_LIMIT] * quotient
        if remainder:
            request_sizes += [remainder]
        outputs = []
        generation_iterator = tqdm.tqdm(request_sizes, leave=False)
        generation_iterator.set_description(self.fullname)
        for request_size in generation_iterator:
            outputs += self._call_cohere_api(prompt, request_size=request_size)
        return outputs


DEFAULT_CLASS = "CohereGenerator"
