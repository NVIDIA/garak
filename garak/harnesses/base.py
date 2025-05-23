# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Base harness

A harness coordinates running probes on a generator, running detectors on the
outputs, and evaluating the results.

This module includes the class Harness, which all `garak` harnesses must
inherit from.
"""

import importlib
import json
import logging
import types
from typing import List

import tqdm

import garak.attempt
from garak import _config
from garak import _plugins
from garak.configurable import Configurable


def _initialize_runtime_services():
    """Initialize and validate runtime services required for a successful test"""

    from garak.exception import GarakException

    # TODO: this block may be gated in the future to ensure it is only run once. At this time
    # only one harness will execute per run so the output here is reasonable.
    service_names = ["garak.langservice"]
    for service_name in service_names:
        logging.info("service import: " + service_name)
        service = importlib.import_module(service_name)
        try:
            if service.enabled():
                symbol, msg = service.start_msg()
                if len(msg):
                    logging.info(msg)
                    print(f"{symbol} {msg}")
                service.load()
        except GarakException as e:
            logging.critical(f"❌ {service_name} setup failed! ❌", exc_info=e)
            raise e


class Harness(Configurable):
    """Class to manage the whole process of probing, detecting and evaluating"""

    active = True

    DEFAULT_PARAMS = {
        "strict_modality_match": False,
    }

    def __init__(self, config_root=_config):
        self._load_config(config_root)

        _initialize_runtime_services()

        logging.info("harness init: %s", self)

    def _load_buffs(self, buff_names: List) -> None:
        """Instantiate specified buffs into global config

        Inheriting classes call _load_buffs in their run() methods. They then call
        garak.harness.base.Harness.run themselves, and so if _load_buffs() is called
        from this base class, we'll end up w/ inefficient reinstantiation of buff
        objects. If one wants to use buffs directly with this harness without
        subclassing, then call this method instance directly.

        Don't use this in the base class's run method, garak.harness.base.Harness.run;
        harnesses should be explicit about how they expect to deal with buffs.
        """

        _config.buffmanager.buffs = []
        for buff_name in buff_names:
            err_msg = None
            try:
                _config.buffmanager.buffs.append(_plugins.load_plugin(buff_name))
                logging.debug("loaded %s", buff_name)
            except ValueError as ve:
                err_msg = f"❌🦾 buff load error:❌ {ve}"
            except Exception as e:
                err_msg = f"❌🦾 failed to load buff {buff_name}:❌ {e}"
            finally:
                if err_msg is not None:
                    print(err_msg)
                    logging.warning(err_msg)
                    continue

    def _start_run_hook(self):
        self._http_lib_user_agents = _config.get_http_lib_agents()
        _config.set_all_http_lib_agents(_config.run.user_agent)

    def _end_run_hook(self):
        _config.set_http_lib_agents(self._http_lib_user_agents)

    def run(self, model, probes, detectors, evaluator, announce_probe=True) -> None:
        """Core harness method

        :param model: an instantiated generator providing an interface to the model to be examined
        :type model: garak.generators.Generator
        :param probes: a list of probe instances to be run
        :type probes: List[garak.probes.base.Probe]
        :param detectors: a list of detectors to use on the results of the probes
        :type detectors: List[garak.detectors.base.Detector]
        :param evaluator: an instantiated evaluator for judging detector results
        :type evaluator: garak.evaluators.base.Evaluator
        :param announce_probe: Should we print probe loading messages?
        :type announce_probe: bool, optional
        """
        if not detectors:
            msg = "No detectors, nothing to do"
            logging.warning(msg)
            if hasattr(_config.system, "verbose") and _config.system.verbose >= 2:
                print(msg)
            raise ValueError(msg)

        if not probes:
            msg = "No probes, nothing to do"
            logging.warning(msg)
            if hasattr(_config.system, "verbose") and _config.system.verbose >= 2:
                print(msg)
            raise ValueError(msg)

        self._start_run_hook()

        for probe in probes:
            logging.debug("harness: probe start for %s", probe.probename)
            if not probe:
                continue

            modality_match = _modality_match(
                probe.modality["in"], model.modality["in"], self.strict_modality_match
            )

            if not modality_match:
                logging.warning(
                    "probe skipped due to modality mismatch: %s - model expects %s",
                    probe.probename,
                    model.modality["in"],
                )
                continue

            attempt_results = probe.probe(model)
            assert isinstance(
                attempt_results, (list, types.GeneratorType)
            ), "probing should always return an ordered iterable"

            for d in detectors:
                logging.debug("harness: run detector %s", d.detectorname)
                attempt_iterator = tqdm.tqdm(attempt_results, leave=False)
                detector_probe_name = d.detectorname.replace("garak.detectors.", "")
                attempt_iterator.set_description("detectors." + detector_probe_name)
                for attempt in attempt_iterator:
                    if d.skip:
                        continue
                    attempt.detector_results[detector_probe_name] = list(
                        d.detect(attempt)
                    )

            for attempt in attempt_results:
                attempt.status = garak.attempt.ATTEMPT_COMPLETE
                _config.transient.reportfile.write(json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n")

            if len(attempt_results) == 0:
                logging.warning(
                    "zero attempt results: probe %s, detector %s",
                    probe.probename,
                    detector_probe_name,
                )
            else:
                evaluator.evaluate(attempt_results)

        self._end_run_hook()

        logging.debug("harness: probe list iteration completed")


def _modality_match(probe_modality, generator_modality, strict):
    if strict:
        # must be perfect match
        return probe_modality == generator_modality
    else:
        # everything probe wants must be accepted by model
        return set(probe_modality).intersection(generator_modality) == set(
            probe_modality
        )
