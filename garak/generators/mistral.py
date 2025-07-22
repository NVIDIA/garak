import backoff
from garak.generators.base import Generator
import garak._config as _config
from mistralai import Mistral, models


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
    def _call_model(self, prompt, generations_this_call=1):
        print(self.name)
        chat_response = self.client.chat.complete(
            model=self.name,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )
        return [chat_response.choices[0].message.content]


DEFAULT_CLASS = "MistralGenerator"
