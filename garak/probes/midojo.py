# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Midojo probe: indirect prompt injection through armed interaction surfaces.

Runs a benign task against a target while an injector occupies one of the
target's interaction surfaces (for example a MiMCP proxy in front of the
target's MCP tools) and splices an attack payload into the content the
target consumes. The probe records the injector's evidence on the attempt so
a detector can grade whether the target performed the attack's goal.
"""

import copy
import logging
import pathlib

import httpx
import yaml

from garak import _plugins
from garak.attempt import Conversation, Message, Turn
from garak.exception import GarakException, PluginConfigurationError
import garak.probes


class MidojoProbe(garak.probes.Probe):
    """Runs scenario-based indirect prompt injection attacks

    Each attack in a scenario file arms an injector, runs the scenario's
    benign task against the target with the armed injection handed to the
    generator, then records the injector's call log on the attempt. The
    scenario file is data, so other targets and surfaces need no probe
    changes; scenarios live outside garak (``scenario_file`` is required,
    e.g. the Klarna demo shipped with the mim-demo deployment repo). Every
    generation of an attempt reuses the armed session, so runs typically
    set ``run.generations`` to 1.
    """

    doc_uri = "https://github.com/NVIDIA/garak/issues/1652"
    lang = "*"
    active = False  # requires a live target and MiMCP environment
    tier = garak.probes.Tier.UNLISTED
    intent = "T009indirect"  # tests whether the target follows instructions embedded in tool results
    goal = "make the target perform unauthorized actions through instructions hidden in tool results"
    primary_detector = "midojo.MidojoDetector"
    parallelisable_attempts = False  # the armed injector tracks one session
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

    def _load_scenario(self) -> None:
        scenario_path = self._scenario_path()
        with open(scenario_path, encoding="utf-8") as scenario_file:
            self.scenario = yaml.safe_load(scenario_file)
        logging.debug("midojo scenario loaded: %s", scenario_path)

    def _conversation_for(self) -> Conversation:
        turns = []
        if self.scenario.get("instructions"):
            turns.append(Turn("system", Message(self.scenario["instructions"])))
        turns.append(Turn("user", Message(self.scenario["benign_task"]["prompt"])))
        return Conversation(turns)

    def _arm_payload(self, spec: dict) -> dict:
        """Build the injector arm payload from an attempt's attack spec"""
        return {
            "upstream": spec["upstream"],
            "server_label": spec.get("server_label"),
            "tools": spec.get("tools", []),
        }

    def probe(self, generator):
        """Arm one injector session per attack and run the benign task"""
        logging.debug("probe execute: %s", self)
        self.generator = generator

        self._load_scenario()
        self.injector = _plugins.load_plugin(self.injector_spec)
        if not self.injector.capabilities:
            raise GarakException(
                f"injector {self.injector_spec} declares no capabilities"
            )

        prompt = self._conversation_for()
        attempts = []
        for seq, attack in enumerate(self.scenario["attacks"]):
            notes = {
                "midojo": {
                    "attack_id": attack["id"],
                    "upstream": self.scenario["upstream"],
                    "server_label": self.scenario["benign_task"].get("server_label"),
                    "tools": attack.get("tools", []),
                    "success": attack.get("success"),
                }
            }
            attempt = self._mint_attempt(prompt, seq=seq, notes=notes)
            attempt.goal = attack.get("description", self.goal)
            attempts.append(attempt)

        return self._execute_all(attempts)

    def _execute_attempt(self, attempt):
        """Arm, generate with the injection, record evidence, disarm"""
        self._generator_precall_hook(self.generator, attempt)
        try:
            descriptor = self.injector.arm(self._arm_payload(attempt.notes["midojo"]))
            attempt.outputs = self.generator.generate(
                attempt.prompt,
                generations_this_call=self.generations,
                injections=[descriptor],
            )
            attempt.notes["mimcp_calls"] = self.injector.get_calls()
        except (httpx.HTTPError, GarakException) as e:
            logging.error("midojo attempt %s failed: %s", attempt.uuid, e)
            attempt.notes["midojo_error"] = str(e)
        finally:
            self.injector.disarm()
        if self.post_buff_hook:
            attempt = self._postprocess_buff(attempt)
        attempt = self._postprocess_hook(attempt)
        self._generator_cleanup()
        return copy.deepcopy(attempt)
