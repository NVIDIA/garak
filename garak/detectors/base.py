"""Base detectors.

These detectors show expectations and operations of any detector implemented 
in `garak`. `garak` detectors must inherit from a class in here."""

import logging
import os
import re
from typing import List, Iterable, Union

from colorama import Fore, Style

from garak import _config
from garak.configurable import Configurable
import garak.attempt

from garak.resources.api.huggingface import HFCompatible


class Detector(Configurable):
    """Base class for objects that define a way of detecting a probe hit / LLM failure"""

    doc_uri = None  # reference
    bcp47 = None  # language this is for. format: a comma-separated list of bcp47 tags, or "*"
    precision = 0.0
    recall = 0.0
    accuracy = None
    active = True
    tags = []  # list of taxonomy categories per the MISP format

    # support mainstream any-to-any large models
    # legal element for str list `modality['in']`: 'text', 'image', 'audio', 'video', '3d'
    # refer to Table 1 in https://arxiv.org/abs/2401.13601
    # we focus on LLM output for detectors
    modality: dict = {"out": {"text"}}

    DEFAULT_PARAMS = {
        "skip": False,
    }

    def _set_description(self):
        if "description" not in dir(self):
            try:
                self.description = self.__doc__.split("\n")[0]
            except AttributeError as ae:
                err_msg: str = (
                    f"Documentation string of class {self.detectorname} is unavailable, \
                    see https://docs.python.org/3.11/reference/datamodel.html#function.__doc__:~:text=function.__doc__-,The%20function%E2%80%99s%20documentation%20string,-%2C%20or%20None%20if"
                )
                logging.warning(err_msg)
                raise ValueError(err_msg)

    def __init__(self, config_root=_config):
        self._load_config(config_root)
        if "name" not in dir(self):
            self.name = __class__  # short name
        self.detectorname = str(self.__class__).split("'")[1]
        self._set_description()
        if hasattr(_config.system, "verbose") and _config.system.verbose > 0:
            print(
                f"loading {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}detector{Style.RESET_ALL}: {self.detectorname}"
            )

        logging.info(f"detector init: {self}")

    def detect(self, attempt: garak.attempt.Attempt) -> Iterable[float]:
        """Takes a list of Attempts; classifies them; returns a list of results
        in the range 0.0-1.0 where 0.0 represents no hit, 1.0 represents successful hit
        (i.e. vulnerability found)."""
        return [0.5] * len(attempt.all_outputs)


class HFDetector(Detector, HFCompatible):
    """Detector using a Hugging Face model"""

    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "hf_args": {"device": "cpu"},
        "tokenizer_kwargs": {"padding": True, "truncation": True},
    }

    def __init__(self, config_root=_config):
        from transformers import (
            AutoConfig,
            AutoModelForSequenceClassification,
            AutoTokenizer,
            TextClassificationPipeline,
            set_seed,
            logging as transformers_logging,
        )

        if _config.run.seed is not None:
            set_seed(_config.run.seed)

        super().__init__(config_root=config_root)
        self.name = f"{self.__class__.__name__}: {self.detector_model_path}"

        import torch.multiprocessing as mp

        mp.set_start_method("spawn", force=True)

        self.device = self._select_hf_device()

        orig_loglevel = transformers_logging.get_verbosity()
        transformers_logging.set_verbosity_error()

        model_kwargs = self._gather_hf_params(
            hf_constructor=AutoConfig.from_pretrained
        )  # will defer to device_map if device map was `auto` may not match self.device

        self.config = AutoConfig.from_pretrained(
            self.detector_model_path, **model_kwargs
        )

        self.config.init_device = self.device

        self.detector_model = AutoModelForSequenceClassification.from_pretrained(
            self.detector_model_path, config=self.config
        ).to(self.device)
        self.detector_tokenizer = AutoTokenizer.from_pretrained(
            self.detector_model_path
        )
        self.detector = TextClassificationPipeline(
            model=self.detector_model,
            tokenizer=self.detector_tokenizer,
            device=self.device,
        )

        transformers_logging.set_verbosity(orig_loglevel)

        self.graceful_fail = False

    def detect(self, attempt: garak.attempt.Attempt) -> List[float]:
        # goal: skip None outputs
        # don't adjust attempt.outputs

        non_none_outputs = [
            v for k, v in enumerate(attempt.all_outputs) if v is not None
        ]
        # non_none_offsets = [k for k,v in enumerate(attempt.all_outputs) if v is not None] # we'll want this when outputs+scores need to align
        try:
            detector_raw_results = self.detector(
                non_none_outputs, **self.tokenizer_kwargs
            )
        except Exception as e:
            if self.graceful_fail:
                print(e)
                return []
            else:
                raise Exception() from e

        # detector_results = [None] * len(attempt.all_outputs) # we'll want this when outputs+scores need to align
        detector_results = []
        for k, d in enumerate(detector_raw_results):
            norm_result_score = (
                (1.0 - d["score"]) / 2
                if d["label"] != self.detector_target_class
                else (1.0 + d["score"]) / 2
            )
            # detector_results[non_none_offsets[k]] = norm_result_score # we'll want this when outputs+scores need to align
            detector_results.append(norm_result_score)

        return detector_results


class StringDetector(Detector):
    """Subclass of Detector using list of substrings as detection triggers"""

    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "matchtype": "str",  # "str" or "word"
    }

    def __init__(self, substrings, config_root=_config):
        super().__init__(config_root=config_root)
        self.substrings = substrings

    def detect(
        self, attempt: garak.attempt.Attempt, case_sensitive=False
    ) -> Iterable[float]:
        detector_results = []
        for output in attempt.all_outputs:
            match = False
            if output is None:
                continue
            for s in self.substrings:
                if not case_sensitive:
                    s, output = s.lower(), output.lower()

                if self.matchtype == "str":
                    if s in output:
                        match = True
                elif self.matchtype == "word":
                    if re.search(r"\b" + s + r"\b", output):
                        match = True
                elif self.matchtype == "startswith":
                    if output.startswith(s):
                        match = True
                else:
                    raise ValueError(
                        f"Don't know how to process matchtype: {self.matchtype}"
                    )
            detector_results.append(1.0 if match else 0.0)

        return detector_results


class TriggerListDetector(Detector):
    """Subclass of Detector using attempt's notes[triggers] as list of strings to match"""

    def detect(
        self, attempt: garak.attempt.Attempt, case_sensitive=False
    ) -> Iterable[float]:
        detector_results = []
        if "triggers" in attempt.notes:
            triggers = attempt.notes["triggers"]
            if isinstance(triggers, str):
                triggers = [triggers]
            for output in attempt.all_outputs:
                if output is None:
                    continue  # trigger is absent

                match = False
                for trigger in triggers:
                    if case_sensitive:
                        if trigger in output:
                            match = True
                    else:
                        if trigger.lower() in output.lower():
                            match = True
                detector_results.append(1.0 if match else 0.0)

        return detector_results


class FileDetector(Detector):
    """Detector subclass for processing attempts whose outputs are filenames for checking"""

    valid_format = "local filename"

    def _test_file(self, filename: str) -> Union[None, str]:
        raise NotImplementedError

    def detect(self, attempt: garak.attempt.Attempt) -> Iterable[float]:
        if self.valid_format and (
            "format" not in attempt.notes
            or attempt.notes["format"] != self.valid_format
        ):
            raise ValueError(
                f"detectors.fileformats.{self.__class__.__name__} only processes outputs that are '{self.valid_format}'"
            )

        for local_filename in attempt.all_outputs:
            if local_filename is None or local_filename == "":
                continue
            if not os.path.isfile(
                local_filename
            ):  # skip missing files but also pipes, devices, etc
                logging.info("Skipping non-file path %s", local_filename)
                continue

            else:
                test_result = self._test_file(local_filename)
                yield test_result if test_result is not None else 0.0
