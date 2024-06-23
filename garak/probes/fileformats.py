# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""File formats probe, looking for potentially vulnerable files.

Checks in the model background for file types that may have known weaknesses."""

import logging
from typing import Iterable, Union

import huggingface_hub

from garak.configurable import Configurable
from garak.probes.base import Probe
import garak.attempt


class HF_Files(Probe, Configurable):
    """Base class for objects that define and execute LLM evaluations"""

    tags: Iterable[str] = []
    goal: str = ""

    # default detector to run, if the primary/extended way of doing it is to be used (should be a string formatted like recommended_detector)
    primary_detector: Union[str, None] = None

    supported_generators = {"Model", "Pipeline", "OptimumPipeline", "LLaVA"}

    # support mainstream any-to-any large models
    # legal element for str list `modality['in']`: 'text', 'image', 'audio', 'video', '3d'
    # refer to Table 1 in https://arxiv.org/abs/2401.13601
    # we focus on LLM input for probe
    modality: dict = {"in": {"text"}}

    def probe(self, generator) -> Iterable[garak.attempt.Attempt]:
        """attempt to exploit the target generator, returning a list of results"""
        logging.debug("probe execute: %s", self)

        package_path = generator.__class__.__module__
        if package_path.split(".")[-1] != "huggingface":
            return []
        if generator.__class__.__name__ not in self.supported_generators:
            return []
        attempt = self._mint_attempt(None)

        filenames = huggingface_hub.list_repo_files(generator.name)
        attempt.outputs = filenames

        logging.debug("probe return: %s with %s filenames", self, len(filenames))

        return [attempt]
