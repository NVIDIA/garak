"""Base Generator

All `garak` generators must inherit from this.
"""

import logging
import re
from typing import List, Union

from colorama import Fore, Style
import tqdm

from garak import _config
from garak.configurable import Configurable
import garak.resources.theme


class Generator(Configurable):
    """Base class for objects that wrap an LLM or other text-to-text service"""

    # avoid class variables for values set per instance
    DEFAULT_PARAMS = {
        "max_tokens": 150,
        "temperature": None,
        "top_k": None,
        "context_len": None,
        "skip_seq_start": None,
        "skip_seq_end": None,
    }

    active = True
    generator_family_name = None
    parallel_capable = True

    # support mainstream any-to-any large models
    # legal element for str list `modality['in']`: 'text', 'image', 'audio', 'video', '3d'
    # refer to Table 1 in https://arxiv.org/abs/2401.13601
    modality: dict = {"in": {"text"}, "out": {"text"}}

    supports_multiple_generations = (
        False  # can more than one generation be extracted per request?
    )

    def __init__(self, name="", config_root=_config):
        self._load_config(config_root)
        if "description" not in dir(self):
            self.description = self.__doc__.split("\n")[0]
        if name:
            self.name = name
        if "fullname" not in dir(self):
            if self.generator_family_name is not None:
                self.fullname = f"{self.generator_family_name}:{self.name}"
            else:
                self.fullname = self.name
        if not self.generator_family_name:
            self.generator_family_name = "<empty>"

        print(
            f"🦜 loading {Style.BRIGHT}{Fore.LIGHTMAGENTA_EX}generator{Style.RESET_ALL}: {self.generator_family_name}: {self.name}"
        )
        logging.info("generator init: %s", self)

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Takes a prompt and returns an API output

        _call_api() is fully responsible for the request, and should either
        succeed or raise an exception. The @backoff decorator can be helpful
        here - see garak.generators.openai for an example usage.

        Can return None if no response was elicited"""
        raise NotImplementedError

    def _pre_generate_hook(self):
        pass

    @staticmethod
    def _verify_model_result(result: List[Union[str, None]]):
        assert isinstance(result, list), "_call_model must return a list"
        assert (
            len(result) == 1
        ), f"_call_model must return a list of one item when invoked as _call_model(prompt, 1), got {result}"
        assert (
            isinstance(result[0], str) or result[0] is None
        ), "_call_model's item must be a string or None"

    def clear_history(self):
        pass

    def _post_generate_hook(self, outputs: List[str | None]) -> List[str | None]:
        return outputs

    def _prune_skip_sequences(self, outputs: List[str | None]) -> List[str | None]:
        rx_complete = (
            re.escape(self.skip_seq_start) + ".*?" + re.escape(self.skip_seq_end)
        )
        rx_missing_final = re.escape(self.skip_seq_start) + ".*?$"

        complete_seqs_removed = [
            (
                re.sub(rx_complete, "", o, flags=re.DOTALL | re.MULTILINE)
                if o is not None
                else None
            )
            for o in outputs
        ]

        partial_seqs_removed = [
            (
                re.sub(rx_missing_final, "", o, flags=re.DOTALL | re.MULTILINE)
                if o is not None
                else None
            )
            for o in complete_seqs_removed
        ]

        return partial_seqs_removed

    def generate(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Manages the process of getting generations out from a prompt

        This will involve iterating through prompts, getting the generations
        from the model via a _call_* function, and returning the output

        Avoid overriding this - try to override _call_model or _call_api
        """

        self._pre_generate_hook()

        assert (
            generations_this_call >= 0
        ), f"Unexpected value for generations_per_call: {generations_this_call}"

        if generations_this_call == 0:
            logging.debug("generate() called with generations_this_call = 0")
            return []

        if generations_this_call == 1:
            outputs = self._call_model(prompt, 1)

        elif self.supports_multiple_generations:
            outputs = self._call_model(prompt, generations_this_call)

        else:
            outputs = []

            if (
                hasattr(_config.system, "parallel_requests")
                and _config.system.parallel_requests
                and isinstance(_config.system.parallel_requests, int)
                and _config.system.parallel_requests > 1
            ):
                from multiprocessing import Pool

                multi_generator_bar = tqdm.tqdm(
                    total=generations_this_call,
                    leave=False,
                    colour=f"#{garak.resources.theme.GENERATOR_RGB}",
                )
                multi_generator_bar.set_description(self.fullname[:55])

                with Pool(_config.system.parallel_requests) as pool:
                    for result in pool.imap_unordered(
                        self._call_model, [prompt] * generations_this_call
                    ):
                        self._verify_model_result(result)
                        outputs.append(result[0])
                        multi_generator_bar.update(1)

            else:
                generation_iterator = tqdm.tqdm(
                    list(range(generations_this_call)),
                    leave=False,
                    colour=f"#{garak.resources.theme.GENERATOR_RGB}",
                )
                generation_iterator.set_description(self.fullname[:55])
                for i in generation_iterator:
                    output_one = self._call_model(
                        prompt, 1
                    )  # generate once as `generation_iterator` consumes `generations_this_call`
                    self._verify_model_result(output_one)
                    outputs.append(output_one[0])

        outputs = self._post_generate_hook(outputs)

        if hasattr(self, "skip_seq_start") and hasattr(self, "skip_seq_end"):
            if self.skip_seq_start is not None and self.skip_seq_end is not None:
                outputs = self._prune_skip_sequences(outputs)

        return outputs
