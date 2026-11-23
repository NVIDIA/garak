# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Loader for indirect prompt injection scenarios, schema 0.3.

A scenario is data: a benign task and the attack cases run against
it. Each case reaches the target through a channel from the catalog
(``garak.channels``) and carries operations against that channel.
Endpoints and the system
prompt belong to the target and injector config, never to the scenario,
so a scenario carries no hostnames and no backend fields. Validation
happens here, at load time, so a malformed scenario fails the run
instead of silently never matching.
"""

import pathlib
from dataclasses import dataclass

import yaml

import garak.channels
from garak.exception import GarakException

SCHEMA_VERSION = "0.3"

# fields earlier schemas carried that moved into the target or injector
# config, with the hint that keeps the migration one step
MOVED_FIELDS = {
    "upstream": "the injector config owns upstream endpoints; declare them on the injector's surfaces",
    "instructions": "the target config owns the system prompt; set the generator's instructions",
}

_CRITERIA_KEYS = {
    "tool_called",
    "output_contains",
    "output_contains_all",
    "output_contains_any",
    "any_of",
    "all_of",
    "not",
}
_TOOL_CALLED_KEYS = {"name", "args", "result_field"}


class ScenarioError(GarakException):
    """A scenario file does not conform to the schema this garak speaks"""


@dataclass(frozen=True)
class Case:
    """One attack case of a scenario.

    ``channel`` is the catalog id the case reaches the target through,
    ``surface`` optionally overrides surface resolution with an internal
    surface name, ``operations`` are the injector vocabulary for the
    attack, and ``success`` holds the criteria a detector grades the
    case by.
    """

    id: str
    description: str | None
    channel: str | None
    surface: str | None
    operations: tuple[dict, ...]
    success: dict | list


@dataclass(frozen=True)
class Scenario:
    """A loaded scenario: a benign task plus its cases."""

    id: str
    description: str | None
    prompt: str
    cases: tuple[Case, ...]


def load_scenario(path) -> Scenario:
    """Load and validate a scenario file.

    Every rejection names the file, the case, and the field, so a
    malformed scenario points at its own fix.
    """
    path = pathlib.Path(path)
    with open(path, encoding="utf-8") as scenario_file:
        document = yaml.safe_load(scenario_file)
    return _scenario_from(document, path)


def _scenario_from(document, path) -> Scenario:
    where = str(path)
    if not isinstance(document, dict):
        raise ScenarioError(f"{where}: the scenario must be a mapping")
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ScenarioError(
            f"{where}: unsupported schema_version {version!r}; "
            f"this garak speaks scenario schema {SCHEMA_VERSION}"
        )
    for moved in MOVED_FIELDS:
        if moved in document:
            raise ScenarioError(
                f"{where}: unknown field {moved!r}: {MOVED_FIELDS[moved]}"
            )
    _reject_unknown(
        document,
        {"schema_version", "id", "description", "benign_task", "cases"},
        where,
        "the scenario",
    )

    scenario_id = _non_empty_str(document.get("id"), where, "the scenario", "id")
    description = document.get("description")
    if description is not None and not isinstance(description, str):
        raise ScenarioError(f"{where}: description must be a string")

    benign_task = document.get("benign_task")
    if not isinstance(benign_task, dict):
        raise ScenarioError(f"{where}: benign_task must be a mapping")
    _reject_unknown(benign_task, {"prompt"}, where, "benign_task")
    prompt = _non_empty_str(benign_task.get("prompt"), where, "benign_task", "prompt")

    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ScenarioError(f"{where}: cases must be a non-empty list")
    cases = tuple(
        _case_from(index, raw_case, where) for index, raw_case in enumerate(raw_cases)
    )
    return Scenario(id=scenario_id, description=description, prompt=prompt, cases=cases)


def _case_from(index: int, raw_case, where: str) -> Case:
    location = f"case {index}"
    if not isinstance(raw_case, dict):
        raise ScenarioError(f"{where}: {location} must be a mapping")
    case_id = _non_empty_str(raw_case.get("id"), where, location, "id")
    location = f"case {case_id!r}"
    _reject_unknown(
        raw_case,
        {"id", "description", "injection", "success"},
        where,
        location,
    )

    description = raw_case.get("description")
    if description is not None and not isinstance(description, str):
        raise ScenarioError(f"{where}: {location}: description must be a string")

    injection = raw_case.get("injection")
    if injection is None:
        raise ScenarioError(f"{where}: {location}: an attack case needs an injection")
    channel, surface, operations = _injection_from(injection, where, location)

    success = raw_case.get("success")
    if success is None:
        raise ScenarioError(f"{where}: {location}: success is required")
    _validate_success(success, where, location)

    return Case(
        id=case_id,
        description=description,
        channel=channel,
        surface=surface,
        operations=operations,
        success=success,
    )


def _injection_from(injection, where: str, location: str):
    if not isinstance(injection, dict):
        raise ScenarioError(f"{where}: {location}: injection must be a mapping")
    _reject_unknown(
        injection, {"channel", "surface", "operations"}, where, f"{location} injection"
    )
    if injection.get("channel") is None:
        raise ScenarioError(f"{where}: {location}: injection.channel is required")
    channel = _channel_id(
        injection.get("channel"), where, location, "injection.channel"
    )
    surface = injection.get("surface")
    if surface is not None:
        surface = _non_empty_str(surface, where, location, "injection.surface")
    raw_operations = injection.get("operations", [])
    if not isinstance(raw_operations, list):
        raise ScenarioError(f"{where}: {location}: injection.operations must be a list")
    operations = []
    for op_index, operation in enumerate(raw_operations):
        if not isinstance(operation, dict):
            raise ScenarioError(
                f"{where}: {location}: injection.operations[{op_index}] must be a mapping"
            )
        _non_empty_str(
            operation.get("op"),
            where,
            f"{location} injection.operations[{op_index}]",
            "op",
        )
        # tool names stay in the operations: they are part of the
        # attack, not of the deployment
        _non_empty_str(
            operation.get("tool"),
            where,
            f"{location} injection.operations[{op_index}]",
            "tool",
        )
        operations.append(operation)
    return channel, surface, tuple(operations)


def _channel_id(value, where: str, location: str, field: str) -> str:
    try:
        return garak.channels.get(value).id
    except ValueError as e:
        raise ScenarioError(f"{where}: {location}: {field}: {e}") from None


def _validate_success(success, where: str, location: str) -> None:
    """Check the criteria vocabulary; a typo'd criterion never matches."""
    if isinstance(success, list):
        for entry in success:
            _validate_success(entry, where, location)
        return
    if not isinstance(success, dict) or not success:
        raise ScenarioError(
            f"{where}: {location}: success must be a non-empty mapping or a list of them"
        )
    _reject_unknown(success, _CRITERIA_KEYS, where, f"{location} success")
    tool_called = success.get("tool_called")
    if tool_called is not None:
        if not isinstance(tool_called, dict):
            raise ScenarioError(
                f"{where}: {location}: success.tool_called must be a mapping"
            )
        _reject_unknown(
            tool_called, _TOOL_CALLED_KEYS, where, f"{location} success.tool_called"
        )
        _non_empty_str(
            tool_called.get("name"), where, f"{location} success.tool_called", "name"
        )
        args = tool_called.get("args")
        if args is not None and not isinstance(args, dict):
            raise ScenarioError(
                f"{where}: {location}: success.tool_called.args must be a mapping"
            )
        result_field = tool_called.get("result_field")
        if result_field is not None:
            if not isinstance(result_field, dict):
                raise ScenarioError(
                    f"{where}: {location}: success.tool_called.result_field must be a mapping"
                )
            _reject_unknown(
                result_field,
                {"path", "equals"},
                where,
                f"{location} success.tool_called.result_field",
            )
            _non_empty_str(
                result_field.get("path"),
                where,
                f"{location} success.tool_called.result_field",
                "path",
            )
            if "equals" not in result_field:
                raise ScenarioError(
                    f"{where}: {location}: success.tool_called.result_field needs an equals value"
                )
    if "output_contains" in success and not isinstance(success["output_contains"], str):
        raise ScenarioError(
            f"{where}: {location}: success.output_contains must be a string"
        )
    for key in ("output_contains_all", "output_contains_any", "any_of", "all_of"):
        if key in success and not isinstance(success[key], list):
            raise ScenarioError(f"{where}: {location}: success.{key} must be a list")
    if "not" in success:
        _validate_success(success["not"], where, location)


def _reject_unknown(mapping, allowed, where: str, location: str) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise ScenarioError(
            f"{where}: {location}: unknown field {unknown[0]!r}; "
            f"allowed are {sorted(allowed)}"
        )


def _non_empty_str(value, where: str, location: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"{where}: {location}: {field} must be a non-empty string")
    return value
