"""OpenRouter LLM interface

Connects to OpenRouter's unified, OpenAI-compatible endpoint, giving access
to hundreds of models hosted by many different providers behind a single
API key.
"""

from typing import List, Union

from garak.attempt import Message, Conversation
from garak.generators.openai import OpenAICompatible


class OpenRouterCompatible(OpenAICompatible):
    """Wrapper for OpenRouter (https://openrouter.ai), a unified API giving
    access to hundreds of models from many different providers.

    Expects the ``OPENROUTER_API_KEY`` environment variable to be set to an
    OpenRouter API key; see https://openrouter.ai/keys for details on
    creating one.

    Model names follow OpenRouter's ``<provider>/<model>`` convention, e.g.
    ``anthropic/claude-sonnet-4``. Browse available models at
    https://openrouter.ai/models.
    """

    ENV_VAR = "OPENROUTER_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "uri": "https://openrouter.ai/api/v1",
        # per https://openrouter.ai/docs/api-reference/parameters and
        # github.com/OpenRouterTeam/openrouter-runner issue 99, `n > 1` is not
        # supported: OpenRouter fans a request out to a single upstream
        # provider per call, so multiple completions require multiple requests.
        "suppressed_params": {"n"},
        # 402 means the account is out of credit -- a convention shared by
        # many inference aggregators, not just OpenRouter. Retrying never
        # helps, and letting it fall through to the default "log and skip"
        # handling would let a long scan run to completion producing nothing
        # but empty results, so it's treated as terminal instead.
        "terminal_status_codes": [402],
    }
    active = True
    supports_multiple_generations = False
    generator_family_name = "OpenRouter"

    def _load_unsafe(self):
        if self.name in ("", None):
            raise ValueError(
                "OpenRouter requires model name to be set, e.g. "
                "--target_name anthropic/claude-sonnet-4\n"
                "Browse available models at https://openrouter.ai/models"
            )
        super()._load_unsafe()

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        if generations_this_call != 1:
            raise AssertionError("generations_per_call / n > 1 is not supported")
        return super()._call_model(prompt, generations_this_call)


DEFAULT_CLASS = "OpenRouterCompatible"
