# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared types for the agent injection contract.

These types are backend-neutral: they name the surfaces a target draws
untrusted content from, the plans that describe what an injector does to
those surfaces, the routes a generator applies, and the evidence an
injection execution produces. Transport details belong to the injectors
and generators, never to these definitions.

A surface kind (for example ``mcp.server``) is a namespaced string. Each
kind defines what its plans, routes, and operations mean; validators on
the injector side reject anything a kind cannot express.
"""

from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any


def as_dict(value: Any) -> Any:
    """Convert a contract value into plain JSON-compatible data.

    Dataclasses become dicts, tuples and sets become lists, and nested
    values convert recursively, so evidence can travel in attempt notes.
    """
    if is_dataclass(value) and not isinstance(value, type):
        return {
            entry.name: as_dict(getattr(value, entry.name)) for entry in fields(value)
        }
    if isinstance(value, (frozenset, set)):
        return sorted(as_dict(entry) for entry in value)
    if isinstance(value, (tuple, list)):
        return [as_dict(entry) for entry in value]
    if isinstance(value, dict):
        return {key: as_dict(entry) for key, entry in value.items()}
    return value


class _ContractType:
    """Mixin giving contract types a JSON-safe dict view."""

    def as_dict(self) -> dict:
        return as_dict(self)


@dataclass(frozen=True)
class SurfaceDescriptor(_ContractType):
    """One interaction surface of a target that garak can occupy.

    ``kind`` is a namespaced string naming the surface kind, for example
    ``mcp.server``; ``name`` identifies the concrete surface within the
    target, for example a configured server label. ``controls`` names the
    operations the target supports on this surface, and ``upstream``
    carries target-owned endpoint data an injector needs to occupy it.
    """

    kind: str
    name: str
    controls: frozenset[str] = frozenset()
    upstream: dict | None = None


@dataclass(frozen=True)
class InjectionPlan(_ContractType):
    """What an injector must do to one surface for one case.

    ``operations`` are plain dicts whose schema the surface kind defines;
    each names one transformation, for example a structured patch on a
    tool result. Injectors reject plans whose surface kind or operations
    they cannot express.
    """

    surface_kind: str
    surface_name: str
    operations: tuple[dict, ...] = ()


@dataclass(frozen=True)
class McpRoute(_ContractType):
    """How a generator routes one MCP server through an injector.

    ``replaces`` is the server label in the target's own tool
    configuration; a generator swaps the configured block carrying that
    label for this route instead of appending a new server.
    """

    replaces: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    transport: str = "streamable_http"


@dataclass(frozen=True)
class ToolCallEvent(_ContractType):
    """One tool call observed on an injected surface.

    ``result`` is the outcome the target saw; ``original_result`` is the
    same result before an injector transformed it, when the surface
    reports both. ``injected`` holds when the injector's payload reached
    the target through this call.
    """

    event_id: str
    tool: str
    arguments: dict
    outcome: str
    result: dict | None = None
    original_result: dict | None = None
    injected: bool = False
    source: str = ""


@dataclass(frozen=True)
class Delivery(_ContractType):
    """Whether and how far an attack payload reached the target."""

    delivered: bool
    injected_calls: int = 0
    recorded_calls: int = 0


@dataclass(frozen=True)
class Coverage(_ContractType):
    """How complete the evidence for one execution is.

    ``target_connected`` and ``recording_complete`` are None when the
    surface cannot report them; ``errors`` carries cleanup or status
    problems so they surface as coverage gaps instead of exceptions.
    """

    target_connected: bool | None = None
    recording_complete: bool | None = None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class InjectionEvidence(_ContractType):
    """Everything one injection execution learned.

    One execution backs one generation: the probe binds a plan to a
    surface, runs one generation through the route, and collects this
    evidence from the binding.
    """

    execution_id: str
    delivery: Delivery
    coverage: Coverage
    events: tuple[ToolCallEvent, ...] = ()


class InjectionBinding:
    """One execution of an injection plan against one surface.

    A binding owns the session state for exactly one generation: ``route``
    is what the generator applies, ``collect_evidence()`` reports what the
    execution learned, and ``close()`` releases the surface. ``close()`` is
    idempotent and must never raise: cleanup failures are logged and
    recorded as coverage errors instead. Bindings work as context
    managers, so a generator exception cannot leak a session.

    Bindings live here rather than in the injectors package because the
    plugin cache treats every class in a plugin directory as a plugin.
    """

    route: object = None

    def __init__(self) -> None:
        self._closed = False
        #: coverage problems learned during this execution; folded into
        #: the evidence by ``collect_evidence()``
        self.coverage_errors: list[str] = []

    def collect_evidence(self) -> InjectionEvidence:
        """Return the evidence this execution collected."""
        raise NotImplementedError

    def close(self) -> None:
        """Release the surface; safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        self._close()

    def _close(self) -> None:
        """Release the surface; subclass hook, runs at most once."""

    def __enter__(self) -> "InjectionBinding":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False
