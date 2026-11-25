"""Atlas Cloud API support"""

from garak.generators.openai import OpenAICompatible


class AtlasCloudChat(OpenAICompatible):
    """Wrapper for Atlas Cloud-hosted LLM models.

    Expects ATLASCLOUD_API_KEY environment variable.
    See https://atlascloud.ai/docs/api-keys for more info on how to set up an
    Atlas Cloud API key.
    Uses the `OpenAI-compatible API <https://atlascloud.ai/docs>`_.

    Model names keep their vendor prefix, e.g.
    ``deepseek-ai/DeepSeek-V3.1-Terminus``. The model catalog is public, so
    ``curl https://api.atlascloud.ai/v1/models`` lists the available names
    without a key.
    """

    ENV_VAR = "ATLASCLOUD_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "uri": "https://api.atlascloud.ai/v1",
        # Checked against the API 2026-10-05: `n`, `logit_bias`, `seed`,
        # `frequency_penalty` and `presence_penalty` are all accepted, but
        # `logprobs` / `top_logprobs` return 400.
        "suppressed_params": {
            "logprobs",
            "top_logprobs",
        },
    }
    active = True
    generator_family_name = "Atlas Cloud"


DEFAULT_CLASS = "AtlasCloudChat"
