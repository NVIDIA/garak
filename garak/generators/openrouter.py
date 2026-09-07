"""OpenRouter LLM interface

Connects to OpenRouter's unified, OpenAI-compatible endpoint, giving access
to hundreds of models hosted by many different providers behind a single
API key.
"""

import functools
import logging
from typing import List, Union

import openai

from garak.attempt import Message, Conversation
from garak.exception import BadGeneratorException
from garak.generators.openai import OpenAICompatible


class OpenRouterGenerator(OpenAICompatible):
    """Wrapper for OpenRouter (https://openrouter.ai), a unified API giving
    access to hundreds of models from many different providers.

    Expects the ``OPENROUTER_API_KEY`` environment variable to be set to an
    OpenRouter API key; see https://openrouter.ai/keys for details on
    creating one.

    Model names follow OpenRouter's ``<provider>/<model>`` convention, e.g.
    ``anthropic/claude-sonnet-4``. Browse available models at
    https://openrouter.ai/models.
    """

    # per https://openrouter.ai/docs/api-reference/parameters and
    # github.com/OpenRouterTeam/openrouter-runner issue 99, `n > 1` is not
    # supported: OpenRouter fans a request out to a single upstream provider
    # per call, so multiple completions require multiple requests.
    ENV_VAR = "OPENROUTER_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "uri": "https://openrouter.ai/api/v1",
        "suppressed_params": {"n"},
    }
    active = True
    supports_multiple_generations = False
    generator_family_name = "OpenRouter"

    @staticmethod
    def _reject_insufficient_credit(create_fn):
        """Wrap an OpenAI-SDK ``create`` callable so that OpenRouter's HTTP 402
        (out of credit) is treated as terminal instead of being logged and
        skipped like other non-transient errors. Retrying a 402 never helps,
        and silently returning ``None`` for every prompt would let a long scan
        run to completion producing nothing but empty results.

        ``functools.wraps`` preserves ``create_fn``'s signature via
        ``__wrapped__`` so that ``OpenAICompatible._call_model``, which
        inspects ``generator.create``'s parameters to build the request, keeps
        seeing the real argument names (``model``, ``messages``, ``n``, ...)
        instead of this wrapper's generic ``*args, **kwargs``.
        """

        @functools.wraps(create_fn)
        def wrapper(*args, **kwargs):
            try:
                return create_fn(*args, **kwargs)
            except openai.APIStatusError as e:
                if e.status_code == 402:
                    msg = (
                        "OpenRouter account has insufficient credit (HTTP 402); "
                        "top up at https://openrouter.ai/credits before retrying."
                    )
                    logging.error(msg)
                    raise BadGeneratorException(msg) from e
                raise

        return wrapper

    def _load_unsafe(self):
        self.client = openai.OpenAI(base_url=self.uri, api_key=self.api_key)
        if self.name in ("", None):
            raise ValueError(
                "OpenRouter requires model name to be set, e.g. "
                "--target_name anthropic/claude-sonnet-4\n"
                "Browse available models at https://openrouter.ai/models"
            )
        self.generator = self.client.chat.completions
        self.generator.create = self._reject_insufficient_credit(self.generator.create)

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        assert (
            generations_this_call == 1
        ), "generations_per_call / n > 1 is not supported"
        return super()._call_model(prompt, generations_this_call)


DEFAULT_CLASS = "OpenRouterGenerator"
