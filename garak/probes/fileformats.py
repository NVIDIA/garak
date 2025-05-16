# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""File formats probe, looking for potentially vulnerable files.

Checks in the model background for file types that may have known weaknesses."""

import logging
from typing import Iterable

import huggingface_hub
import tqdm

from garak import _config
import garak.attempt
import garak.probes
import garak.resources.theme


class HF_Files(garak.probes.Probe):
    """Get a manifest of files associated with a Hugging Face generator

    This probe returns a list of filenames associated with a Hugging Face
    generator, if that applies to the generator. Not enabled for all types,
    e.g. some endpoints."""

    lang = "*"
    tags = ["owasp:llm05"]
    goal = "get a list of files associated with the model"
    tier = garak.probes.Tier.OF_CONCERN

    # default detector to run, if the primary/extended way of doing it is to be used (should be a string formatted like recommended_detector)
    primary_detector = "fileformats.FileIsPickled"
    extended_detectors = [
        "fileformats.FileIsExecutable",
        "fileformats.PossiblePickleName",
    ]
    active = False

    supported_generators = {"Model", "Pipeline", "OptimumPipeline", "LLaVA"}

    # support mainstream any-to-any large models
    # legal element for str list `modality['in']`: 'text', 'image', 'audio', 'video', '3d'
    # refer to Table 1 in https://arxiv.org/abs/2401.13601
    # we focus on LLM input for probe
    modality: dict = {"in": {"text"}}

    def __init__(self, config_root=_config):
        self._load_config(config_root)
        super().__init__(config_root=config_root)

    def probe(self, generator) -> Iterable[garak.attempt.Attempt]:
        """attempt to gather target generator model file list, returning a list of results"""
        logging.debug("probe execute: %s", self)

        package_path = generator.__class__.__module__
        if package_path.split(".")[-1] != "huggingface":
            return []
        if generator.__class__.__name__ not in self.supported_generators:
            return []
        attempt = self._mint_attempt(generator.name)

        repo_filenames = huggingface_hub.list_repo_files(generator.name)
        local_filenames = []
        for repo_filename in tqdm.tqdm(
            repo_filenames,
            leave=False,
            desc=f"Gathering files in {generator.name}",
            colour=f"#{garak.resources.theme.PROBE_RGB}",
        ):
            local_filename = huggingface_hub.hf_hub_download(
                generator.name, repo_filename, force_download=False
            )
            local_filenames.append(local_filename)

        attempt.notes["format"] = "local filename"
        attempt.outputs = local_filenames

        logging.debug("probe return: %s with %s filenames", self, len(local_filenames))

        return [attempt]
