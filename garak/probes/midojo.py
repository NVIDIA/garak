# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Midojo probe: indirect prompt injection through occupied interaction surfaces.

Runs a benign task against a target while an injector occupies one of the
target's interaction surfaces (for example a MiMCP proxy in front of the
target's MCP tools) and splices an attack payload into the content the
target consumes. The probe records the executions' evidence on the
attempt so a detector can grade whether the target performed the attack's
goal.
"""

import copy
import logging
import pathlib

from garak import _plugins
from garak.attempt import Conversation, Message, Turn
from garak.exception import GarakException, InjectorError, PluginConfigurationError
from garak.injection import InjectionPlan
from garak.probes._scenario import Case, load_scenario
import garak.probes


class MidojoProbe(garak.probes.Probe):
    """Runs scenario-based indirect prompt injection attacks

    Each case in a schema 0.2 scenario file names the surface it attacks;
    the probe resolves that surface against the target's injectable
    surfaces, validates the case's plan on it, and binds one injector
    session per generation, so ``run.generations`` samples model
    variation while the recorded evidence stays attributed to a single
    output. Control cases (``kind: control``) run the benign task without
    an injection. The scenario file is data, so other targets and surfaces
    need no probe changes; scenarios live outside garak
    (``scenario_file`` is required, e.g. the Klarna demo shipped with the
    mim-demo deployment repo).
    """

    doc_uri = "https://github.com/NVIDIA/garak/issues/1652"
    lang = "*"
    active = False  # requires a live target and injector environment
    tier = garak.probes.Tier.UNLISTED
    intent = "T009indirect"  # tests whether the target follows instructions embedded in tool results
    goal = "make the target perform unauthorized actions through instructions hidden in tool results"
    primary_detector = "midojo.MidojoDetector"
    parallelisable_attempts = False  # one report sink; evidence stays per-attempt
    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
    ]

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "scenario_file": None,
        "injector_spec": "injectors.mimcp.MiMCPInjector",
    }

    def _scenario_path(self) -> pathlib.Path:
        if not self.scenario_file:
            raise PluginConfigurationError(
                "MidojoProbe requires a scenario_file; the Klarna demo scenario "
                "ships with the mim-demo deployment repo"
            )
        return pathlib.Path(self.scenario_file)

    def probe(self, generator):
        """Resolve each case's surface and run the benign task per case"""
        logging.debug("probe execute: %s", self)
        self.generator = generator

        scenario = load_scenario(self._scenario_path())
        self.injector = _plugins.load_plugin(self.injector_spec)
        if not self.injector.surface_kinds:
            raise GarakException(
                f"injector {self.injector_spec} occupies no surface kinds"
            )

        surfaces = {
            (surface.kind, surface.name): surface
            for surface in generator.injectable_surfaces()
        }
        prompt = Conversation([Turn("user", Message(scenario.prompt))])
        attempts = []
        self._cases: dict[int, tuple[Case, object, InjectionPlan | None]] = {}
        for seq, case in enumerate(scenario.cases):
            surface = plan = None
            if case.kind == "attack":
                surface = surfaces.get((case.surface_kind, case.surface_name))
                if surface is None:
                    raise GarakException(
                        f"the target offers no surface "
                        f"{case.surface_kind}/{case.surface_name}; configure it "
                        "in the generator's tools"
                    )
                plan = InjectionPlan(
                    surface_kind=case.surface_kind,
                    surface_name=case.surface_name,
                    operations=case.operations,
                )
                self.injector.validate(plan, surface)
            self._cases[seq] = (case, surface, plan)
            notes = {
                "midojo": {
                    "scenario_id": scenario.id,
                    "case_id": case.id,
                    "case_kind": case.kind,
                    "success": case.success,
                    "plan": plan.as_dict() if plan is not None else None,
                    "executions": [],
                }
            }
            attempt = self._mint_attempt(prompt, seq=seq, notes=notes)
            attempt.goal = case.description or self.goal
            attempts.append(attempt)

        return self._execute_all(attempts)

    @staticmethod
    def _undelivered_execution(execution_id: str, error: str | None = None) -> dict:
        """Evidence for a generation no payload was delivered through."""
        return {
            "execution_id": execution_id,
            "delivery": {
                "delivered": False,
                "injected_calls": 0,
                "recorded_calls": 0,
            },
            "coverage": {
                "target_connected": None,
                "recording_complete": None,
                "errors": [error] if error else [],
            },
            "events": [],
        }

    def _execute_attempt(self, attempt):
        """Bind one session per generation, keeping evidence attributed

        Each generation runs through its own binding, so the recorded
        evidence belongs to exactly one model output: a detector score
        then reflects that generation's behaviour and not another one's.
        A generation the injector or generator cannot support fails
        closed: it records undelivered evidence and scores as
        inconclusive, never as safe.
        """
        self._generator_precall_hook(self.generator, attempt)
        case, surface, plan = self._cases[attempt.seq]
        outputs = []
        executions = []
        for generation in range(self.generations):
            execution_id = f"{attempt.uuid}-{generation}"
            try:
                if plan is None:
                    outputs.extend(
                        self.generator.generate(attempt.prompt, generations_this_call=1)
                    )
                    executions.append(self._undelivered_execution(execution_id))
                else:
                    binding = self.injector.bind(plan, surface, execution_id)
                    try:
                        outputs.extend(
                            self.generator.generate(
                                attempt.prompt,
                                generations_this_call=1,
                                injection_routes=[binding.route],
                            )
                        )
                        evidence = binding.collect_evidence()
                    finally:
                        binding.close()
                    executions.append(evidence.as_dict())
            except InjectorError as e:
                logging.error(
                    "midojo attempt %s execution %s failed: %s",
                    attempt.uuid,
                    execution_id,
                    e,
                )
                attempt.notes["midojo_error"] = str(e)
                outputs.append(garak.attempt.Message(None))
                executions.append(self._undelivered_execution(execution_id, str(e)))
        attempt.outputs = outputs
        attempt.notes["midojo"]["executions"] = executions
        if self.post_buff_hook:
            attempt = self._postprocess_buff(attempt)
        attempt = self._postprocess_hook(attempt)
        self._generator_cleanup()
        return copy.deepcopy(attempt)
