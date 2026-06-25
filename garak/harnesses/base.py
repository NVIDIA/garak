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

from garak import _config
from garak import _plugins
from garak.configurable import Configurable
import garak.attempt
import garak.probes.base


def _initialize_runtime_services():
    """Initialize and validate runtime services required for a successful test"""

    from garak.exception import GarakException

    # TODO: this block may be gated in the future to ensure it is only run once. At this time
    # only one harness will execute per run so the output here is reasonable.
    service_names = ["langservice", "intentservice"]
    for service_name in service_names:
        logging.info("service import: " + service_name)
        service = importlib.import_module(f"garak.services.{service_name}")
        try:
            if service.enabled():
                symbol, msg = service.start_msg()
                if len(msg):
                    logging.info(msg)
                    print(f"{symbol} {msg}")
                service.load()
        except GarakException as e:
            logging.critical("❌ %s setup failed!" % service_name, exc_info=e)
            raise e


def _emit_plugin_cache_entry(*plugin_instances) -> None:
    snapshot = {}
    for plugin_instance in plugin_instances:
        if plugin_instance is None:
            continue
        classpath = (
            f"{plugin_instance.__class__.__module__}."
            f"{plugin_instance.__class__.__name__}"
        ).replace("garak.", "")
        category = classpath.split(".")[0]
        meta = _plugins.PluginCache.plugin_info(classpath)
        snapshot.setdefault(category, {})[classpath] = meta

    if not snapshot:
        return

    snapshot["version"] = garak.__version__
    _config.transient.reportfile.write(
        json.dumps(
            {
                "entry_type": "plugin_cache",
                "run": _config.transient.run_id,
                "plugin_cache": snapshot,
            },
            cls=_plugins.PluginEncoder,
            ensure_ascii=False,
        )
        + "\n"
    )


class Harness(Configurable):
    """Class to manage the whole process of probing, detecting and evaluating"""

    active = True
    # list of strings naming modules required but not explicitly in garak by default
    extra_dependency_names = []

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

    def _run_detector(self, probe_result_attempts, detector_instance) -> None:
        logging.debug("harness: run detector %s", detector_instance.detectorname)
        attempt_iterator = tqdm.tqdm(probe_result_attempts, leave=False)
        detector_probe_name = detector_instance.detectorname.replace(
            "garak.detectors.", ""
        )
        attempt_iterator.set_description("detectors." + detector_probe_name)
        for attempt in attempt_iterator:
            if detector_instance.skip:
                continue
            attempt.detector_results[detector_probe_name] = list(
                detector_instance.detect(attempt)
            )

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
        _emit_plugin_cache_entry(
            self,
            model,
            *probes,
            *detectors,
            *_config.buffmanager.buffs,
        )

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

            if not isinstance(probe, garak.probes.base.IntentProbe):
                for d in detectors:
                    self._run_detector(attempt_results, d)

            else:
                # extract detectors to be run
                detectors_required = set()
                intents_observed = set()
                # determine candidate detectors
                attempt_results_list = list(attempt_results)
                intent_to_detector = {}
                probe_detector_names = {
                    d.detectorname.replace("garak.detectors.", "") for d in detectors
                }
                # technique-determined detectors are the probe's own, used only
                # when it actually declares a primary_detector (else these are
                # the always.Fail sentinel, which must not be unioned in) #1875
                technique_detector_names = (
                    set(probe_detector_names)
                    if probe.primary_detector is not None
                    else set()
                )

                for a in attempt_results_list:
                    intent = a.intent
                    if not intent:
                        logging.warning(
                            "probe %s attempt %s seq %s has no or empty intent"
                            % (probe.probename, a.uuid, a.seq)
                        )
                    intents_observed.add(intent)

                if intents_observed:
                    from garak.services import intentservice

                for intent_observed in intents_observed:
                    intent_detector_names = intentservice.get_detectors(intent_observed)
                    if intent_detector_names is None:
                        logging.warning(
                            "No detectors specified for intent %s" % intent_observed
                        )
                        intent_detector_names = set()
                    # select detectors by technique as well as intent: union the
                    # probe's technique detectors with the intent-mapped ones
                    # rather than using the probe's only as fallback (#1875)
                    mapping = technique_detector_names | set(intent_detector_names)
                    if not mapping:
                        # no technique or intent detector; keep the probe's own
                        # (always.Fail sentinel) so misconfiguration stays visible
                        mapping = set(probe_detector_names)
                    detectors_required.update(mapping)
                    intent_to_detector[intent_observed] = mapping

                logging.info(
                    "For probe %s, selected detectors %s based on intents"
                    % (probe.probename, repr(detectors_required))
                )

                intent_detectors = []
                for detector_name in detectors_required:
                    d = _plugins.load_plugin(f"detectors.{detector_name}")
                    intent_detectors.append(d)
                    attempt_subset = []
                    for a in attempt_results_list:
                        mapping = intent_to_detector[a.intent]
                        if detector_name in mapping:
                            attempt_subset.append(a)
                    self._run_detector(attempt_subset, d)

                # detectors resolved via the intent path are not in the
                # harness-level detector list snapshotted at run start, so emit
                # them here to keep report.jsonl plugin_cache complete
                _emit_plugin_cache_entry(*intent_detectors)
                del intent_detectors

            for attempt in attempt_results:
                attempt.status = garak.attempt.ATTEMPT_COMPLETE
                _config.transient.reportfile.write(
                    json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n"
                )

            if len(attempt_results) == 0:
                logging.warning("zero attempt results: probe %s" % probe.probename)

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
