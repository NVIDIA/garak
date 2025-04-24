# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Base classes for buffs. """

from collections.abc import Iterable
import logging
from typing import List

from colorama import Fore, Style
import tqdm

import garak.attempt
from garak import _config
from garak.configurable import Configurable


class Buff(Configurable):
    """Base class for a buff.

    A buff should take as input a list of attempts, and return
    a list of events. It should be able to return a generator.
    It's worth storing the origin attempt ID in the notes attrib
    of derivative attempt objects.
    """

    doc_uri = ""
    lang = None  # set of languages this buff should be constrained to
    active = True

    DEFAULT_PARAMS = {}

    def __init__(self, config_root=_config) -> None:
        self._load_config(config_root)
        module = self.__class__.__module__.replace("garak.buffs.", "")
        self.fullname = f"{module}.{self.__class__.__name__}"
        self.post_buff_hook = False
        print(
            f"🦾 loading {Style.BRIGHT}{Fore.LIGHTGREEN_EX}buff: {Style.RESET_ALL}{self.fullname}"
        )
        logging.info("buff init: %s", self)

    def _derive_new_attempt(
        self, source_attempt: garak.attempt.Attempt, seq=-1
    ) -> garak.attempt.Attempt:
        if seq == -1:
            seq = source_attempt.seq
        new_attempt = garak.attempt.Attempt(
            status=source_attempt.status,
            prompt=source_attempt.prompt,
            probe_classname=source_attempt.probe_classname,
            probe_params=source_attempt.probe_params,
            targets=source_attempt.targets,
            notes=source_attempt.notes,
            detector_results=source_attempt.detector_results,
            goal=source_attempt.goal,
            seq=seq,
        )
        new_attempt.notes["buff_creator"] = self.__class__.__name__
        new_attempt.notes["buff_source_attempt_uuid"] = str(
            source_attempt.uuid
        )  # UUIDs don't serialise nicely
        new_attempt.notes["buff_source_seq"] = source_attempt.seq

        return new_attempt

    def transform(
        self, attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        """attempt copying is handled elsewhere. isn't that nice"""
        yield self._derive_new_attempt(attempt)

    def untransform(self, attempt: garak.attempt.Attempt) -> garak.attempt.Attempt:
        """Only necessary if buff requires a post buff hook"""
        pass

    def buff(
        self, source_attempts: List[garak.attempt.Attempt], probename=""
    ) -> Iterable[garak.attempt.Attempt]:
        for source_attempt in tqdm.tqdm(
            source_attempts,
            desc=f"📥 Buffing probe: {probename}/{self.fullname}",
            leave=False,
        ):
            # create one or more untransformed new attempts
            # don't include the original attempt/prompt in the buffs: https://github.com/NVIDIA/garak/issues/373
            new_attempts = []
            new_attempts.append(
                self._derive_new_attempt(source_attempt, source_attempt.seq)
            )
            for new_attempt in new_attempts:
                for transformed_new_attempt in self.transform(new_attempt):
                    # transform can returns multiple results
                    yield transformed_new_attempt
