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
from garak.exception import BudgetExceededError


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
    # list of strings naming modules required but not explicitly in garak by default
    extra_dependency_names = []

    DEFAULT_PARAMS = {
        "strict_modality_match": False,
    }

    def __init__(self, config_root=_config):
        self._load_config(config_root)

        _initialize_runtime_services()

        # Initialize budget manager if usage tracking or limits are configured
        # Note: track_usage is auto-enabled by CLI when cost/token limits are set
        self.budget_manager = None
        if hasattr(_config, "run"):
            track_usage = getattr(_config.run, "track_usage", False)
            cost_limit = getattr(_config.run, "cost_limit", None)
            token_limit = getattr(_config.run, "token_limit", None)

            if track_usage:
                from garak.budget import BudgetManager

                self.budget_manager = BudgetManager(
                    cost_limit=cost_limit,
                    token_limit=token_limit,
                )
                # Initialize shared state for multiprocessing budget enforcement
                # Pass model name for accurate cost calculation in workers
                model_name = getattr(_config.plugins, "target_name", None)
                self.budget_manager.init_shared_state(model=model_name)
                logging.info(
                    "Budget tracking enabled: cost_limit=%s, token_limit=%s",
                    cost_limit,
                    token_limit,
                )

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

    def _collect_usage_from_attempt(self, attempt) -> None:
        """Extract and record token usage from attempt outputs.

        NOTE: Usage is now recorded immediately in the generator's _post_generate_hook
        for faster budget enforcement in parallel execution. This method is kept for
        backwards compatibility with generators that may not call _post_generate_hook
        or for cases where the budget_manager wasn't available at generation time.

        Looks for 'token_usage' in each output Message's notes field.
        Only records if the usage hasn't already been recorded (checked via usage_log).
        """
        if self.budget_manager is None:
            return

        from garak.budget import TokenUsage

        for output in attempt.outputs:
            if output is None:
                continue
            if hasattr(output, "notes") and output.notes:
                usage_data = output.notes.get("token_usage")
                if usage_data:
                    # Check if this usage was already recorded by checking timestamp
                    # Usage is now recorded immediately in generator._post_generate_hook
                    # so we skip to avoid double-counting
                    timestamp = usage_data.get("timestamp")
                    already_recorded = any(
                        u.timestamp == timestamp for u in self.budget_manager.usage_log
                    )
                    if already_recorded:
                        continue

                    try:
                        usage = TokenUsage(**usage_data)
                        self.budget_manager.record_usage(usage)
                    except BudgetExceededError:
                        # Don't re-raise here - let all attempts complete status update
                        # The budget check after evaluation will raise the exception
                        logging.debug("Budget exceeded during usage collection, will raise after evaluation")
                    except Exception as e:
                        logging.warning("Failed to record usage: %s", e)

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
                _config.transient.reportfile.write(
                    json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n"
                )

                # Aggregate token usage from attempt outputs if budget tracking is enabled
                if self.budget_manager is not None:
                    self._collect_usage_from_attempt(attempt)

            if len(attempt_results) == 0:
                logging.warning(
                    "zero attempt results: probe %s, detector %s",
                    probe.probename,
                    detector_probe_name,
                )
            else:
                evaluator.evaluate(attempt_results)

            # Check if budget was exceeded during this probe
            # If so, stop processing more probes but let this one complete evaluation
            from garak.budget import is_budget_exceeded, get_shared_usage
            if is_budget_exceeded() and self.budget_manager:
                shared_tokens, shared_cost, _, _, _ = get_shared_usage()
                token_limit = self.budget_manager.token_limit
                cost_limit = self.budget_manager.cost_limit
                if token_limit and shared_tokens > token_limit:
                    logging.info("Budget exceeded after probe evaluation, stopping")
                    self._end_run_hook()
                    raise BudgetExceededError(
                        f"Token limit exceeded: {shared_tokens:,} tokens used, "
                        f"limit is {token_limit:,} tokens"
                    )
                if cost_limit and shared_cost > cost_limit:
                    logging.info("Cost limit exceeded after probe evaluation, stopping")
                    self._end_run_hook()
                    raise BudgetExceededError(
                        f"Cost limit exceeded: ${shared_cost:.4f} spent, "
                        f"limit is ${cost_limit:.2f}"
                    )

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
