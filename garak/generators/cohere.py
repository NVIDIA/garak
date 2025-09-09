"""Cohere AI model support

Support for Cohere's text generation API. Uses the command model by default,
but just supply the name of another either on the command line or as the
constructor param if you want to use that. You'll need to set an environment
variable called COHERE_API_KEY to your Cohere API key, for this generator.

NOTE: As of Cohere v5.0.0+, the generate API is legacy and chat API is recommended.
This implementation follows Cohere's official migration guide:
- For v1 API: Uses cohere.Client() to maintain full backward compatibility
- For v2 API: Uses cohere.ClientV2() for the recommended chat interface
"""

import logging
from typing import List, Union

import backoff
from cohere.core.api_error import ApiError
import cohere
import tqdm

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


COHERE_GENERATION_LIMIT = (
    5  # c.f. https://docs.cohere.com/reference/generate 18 may 2023
)


class CohereGenerator(Generator):
    """Interface to Cohere's python library for their text2text model.

    Expects API key in COHERE_API_KEY environment variable.

    Following Cohere's migration guide, this implementation:
    - For api_version="v1": Uses cohere.Client() with generate() API (supports multiple generations)
    - For api_version="v2": Uses cohere.ClientV2() with chat() API (recommended, requires multiple API calls)
    """

    ENV_VAR = "COHERE_API_KEY"
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "temperature": 0.750,
        "k": 0,
        "p": 0.75,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0,
        "stop": [],  # Used for end_sequences in v1 API
        "preset": None,  # Only used with v1 API
        "api_version": "v2",  # "v1" for legacy generate API, "v2" for chat API (recommended)
    }

    generator_family_name = "Cohere"

    def __init__(self, name="command", config_root=_config):
        self.name = name
        self.fullname = f"Cohere {self.name}"

        super().__init__(self.name, config_root=config_root)

        logging.debug(
            "Cohere generation request limit capped at %s", COHERE_GENERATION_LIMIT
        )

        # Validate api_version
        if self.api_version not in ["v1", "v2"]:
            logging.warning(
                f"Invalid api_version '{self.api_version}'. Using 'v2' instead."
            )
            self.api_version = "v2"

        # Initialize appropriate client based on API version
        # Following Cohere's guidance to use Client() for v1 and ClientV2() for v2
        if self.api_version == "v1":
            self.generator = cohere.Client(api_key=self.api_key)
        else:  # api_version == "v2"
            self.generator = cohere.ClientV2(api_key=self.api_key)

    @backoff.on_exception(backoff.fibo, ApiError, max_value=70)
    def _call_cohere_api(self, prompt_text, request_size=COHERE_GENERATION_LIMIT):
        """Empty prompts raise API errors (e.g. invalid request: prompt must be at least 1 token long).
        We catch these using the ApiError base class in Cohere v5+.
        Filtering exceptions based on message instead of type, in backoff, isn't immediately obvious
        - on the other hand blank prompt / RTP shouldn't hang forever
        """
        if not prompt_text:
            return [Message("")] * request_size
        else:
            if self.api_version == "v2":
                # Use chat API with ClientV2 (recommended in v5+)
                responses = []
                # Chat API doesn't support num_generations, so we need to make multiple calls
                for _ in range(request_size):
                    try:
                        response = self.generator.chat(
                            model=self.name,
                            messages=prompt_text,
                            temperature=self.temperature,
                            max_tokens=self.max_tokens,
                            k=self.k,
                            p=self.p,
                            frequency_penalty=self.frequency_penalty,
                            presence_penalty=self.presence_penalty,
                            # Note: stop_sequences/end_sequences, logit_bias, truncate, and preset
                            # are not supported in the Chat endpoint per Cohere migration guide
                        )

                        # Extract text from message content
                        if hasattr(response, "message") and hasattr(
                            response.message, "content"
                        ):
                            # Get the first text content item
                            for content_item in response.message.content:
                                if hasattr(content_item, "text"):
                                    responses.append(content_item.text)
                                    break
                            else:
                                # No text content found
                                logging.warning(
                                    "No text content found in chat response"
                                )
                                responses.append(str(response))
                        else:
                            logging.warning(
                                "Chat response structure doesn't match expected format"
                            )
                            responses.append(str(response))
                    except ApiError as e:
                        raise e  # bubble up ApiError for backoff handling
                    except Exception as e:
                        logging.error(f"Chat API error: {e}")
                        responses.append(None)

                # Ensure we return the correct number of responses
                if len(responses) < request_size:
                    responses.extend([None] * (request_size - len(responses)))
                return responses
            else:  # api_version == "v1"
                # Use legacy generate API with cohere.Client()
                # Following Cohere's guidance for full backward compatibility
                try:
                    message = prompt_text[-1]["content"]

                    response = self.generator.generate(
                        model=self.name,
                        prompt=message,
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

                    # Handle response based on structure
                    if hasattr(response, "generations"):
                        # Handle the v5+ API response format
                        return [gen.text for gen in response.generations]
                    else:
                        # Try to handle other possible response formats
                        try:
                            if isinstance(response, list):
                                return [g.text for g in response]
                            elif hasattr(response, "text"):
                                return [response.text]
                            else:
                                # Last resort - try to convert response to string
                                return [str(response)]
                        except RuntimeError as e:
                            logging.error(
                                f"Failed to extract text from Cohere response: {e}"
                            )
                            return [None] * request_size
                except RuntimeError as e:
                    logging.error(f"Generate API error: {e}")
                    return [None] * request_size

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
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
            outputs += self._call_cohere_api(
                self._conversation_to_list(prompt), request_size=request_size
            )
        return outputs


DEFAULT_CLASS = "CohereGenerator"
