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

import garak.channels
from garak import _config
from garak.attempt import Conversation, Message, Turn
from garak.exception import GarakException, InjectorError, PluginConfigurationError
from garak.injection import InjectionPlan, Surface
from garak.probes._scenario import Case, load_scenario
import garak.probes


class MidojoProbe(garak.probes.Probe):
    """Runs scenario-based indirect prompt injection attacks

    Each case in a schema 0.3 scenario file names the channel it reaches
    the target through; the probe resolves that channel against the
    surfaces the loaded injectors offer (selected with run.spec, like
    buffs), validates the case's plan on the surface, checks the target
    can apply the patch the surface needs, and binds one injector session
    per generation, so ``run.generations`` samples model variation while
    the recorded evidence stays attributed to a single output. A case
    whose channel no loaded surface offers, or whose patch the target
    cannot apply, is unsupported and scores None, never safe. The
    scenario file is data, so other targets and surfaces need no probe
    changes; scenarios live outside garak (``scenario_file`` is required,
    e.g. the Klarna demo shipped with the mim-demo deployment repo).
    """

    doc_uri = "https://github.com/NVIDIA/garak/issues/1652"
    lang = "*"
    active = False  # requires a live target and injector environment
    tier = garak.probes.Tier.UNLISTED
    intent = "T009indirect"  # tests whether the target follows instructions embedded in tool results
    goal = "make the target perform unauthorized actions through instructions hidden in tool results"
    primary_detector = "midojo.MidojoDetector"
    parallelisable_attempts = False  # one report sink; evidence stays per-attempt
    # scenario-driven: any channel a loaded injector offers
    supported_channels = frozenset(garak.channels.CHANNELS)
    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
    ]

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "scenario_file": None,
    }

    def _scenario_path(self) -> pathlib.Path:
        if not self.scenario_file:
            raise PluginConfigurationError(
                "MidojoProbe requires a scenario_file; the Klarna demo scenario "
                "ships with the mim-demo deployment repo"
            )
        return pathlib.Path(self.scenario_file)

    def _resolve_case(self, case: Case, generator):
        """Preflight one case against the loaded surfaces.

        Returns (injector, surface, plan, unsupported_reason). A missing
        surface or an inapplicable patch marks the case unsupported; a
        channel several surfaces offer, or a plan the injector rejects,
        aborts the run as a configuration error.
        """
        candidates = _config.injectormanager.surfaces_for_channel(case.channel)
        if case.surface is not None:
            candidates = [pair for pair in candidates if pair[1].name == case.surface]
            if not candidates:
                raise GarakException(
                    f"case {case.id!r} names surface {case.surface!r}, which no "
                    f"loaded injector offers on the {case.channel} channel"
                )
        if len(candidates) > 1:
            needed = {
                operation["tool"]
                for operation in case.operations
                if operation.get("tool")
            }
            if needed:
                candidates = [
                    pair for pair in candidates if needed <= set(pair[1].tools)
                ]
        if not candidates:
            return (
                None,
                None,
                None,
                (f"no loaded surface offers the {case.channel} channel"),
            )
        if len(candidates) > 1:
            names = ", ".join(sorted(pair[1].name for pair in candidates))
            raise GarakException(
                f"case {case.id!r}: several surfaces offer the {case.channel} "
                f"channel ({names}); name one through injection.surface"
            )
        injector, surface = candidates[0]
        plan = InjectionPlan(
            channel=case.channel,
            operations=case.operations,
            surface=case.surface,
        )
        injector.validate(plan, surface)
        patch_kind = (surface.attach or {}).get("patch")
        if patch_kind and patch_kind not in generator.supported_patches:
            return (
                injector,
                surface,
                plan,
                (
                    f"the target cannot apply the {patch_kind} patch the surface "
                    f"{surface.name!r} needs"
                ),
            )
        return injector, surface, plan, None

    def probe(self, generator):
        """Resolve each case's surface and run the benign task per case"""
        logging.debug("probe execute: %s", self)
        self.generator = generator

        scenario = load_scenario(self._scenario_path())
        prompt = Conversation([Turn("user", Message(scenario.prompt))])
        attempts = []
        self._cases: dict[
            int, tuple[Case, object, Surface | None, InjectionPlan | None, str | None]
        ] = {}
        for seq, case in enumerate(scenario.cases):
            injector, surface, plan, unsupported = self._resolve_case(case, generator)
            self._cases[seq] = (case, injector, surface, plan, unsupported)
            trust = garak.channels.get(case.channel).trust if case.channel else None
            notes = {
                "midojo": {
                    "scenario_id": scenario.id,
                    "case_id": case.id,
                    "channel": case.channel,
                    "trust": trust,
                    "surface": surface.name if surface is not None else None,
                    "success": case.success,
                    "plan": plan.as_dict() if plan is not None else None,
                    "mcp_require_approval": getattr(
                        generator, "mcp_require_approval", None
                    ),
                    "executions": [],
                }
            }
            if unsupported:
                notes["midojo"]["unsupported"] = unsupported
                logging.warning(
                    "midojo case %s is unsupported: %s", case.id, unsupported
                )
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
        case, injector, surface, plan, unsupported = self._cases[attempt.seq]
        outputs = []
        executions = []
        for generation in range(self.generations):
            execution_id = f"{attempt.uuid}-{generation}"
            if unsupported:
                outputs.append(garak.attempt.Message(None))
                executions.append(self._undelivered_execution(execution_id))
                continue
            try:
                binding = injector.bind(plan, surface, execution_id)
                try:
                    patches = (
                        [binding.target_patch]
                        if binding.target_patch is not None
                        else None
                    )
                    outputs.extend(
                        self.generator.generate(
                            attempt.prompt,
                            generations_this_call=1,
                            target_patches=patches,
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
