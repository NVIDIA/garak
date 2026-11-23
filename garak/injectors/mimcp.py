# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""MiMCP injector: occupies tool_result surfaces through a MiMCP proxy session."""

import logging
import os

import httpx

from garak import _config
import garak.channels
from garak.exception import InjectorError, InvalidInjectionPlanError
from garak.injection import (
    Coverage,
    Delivery,
    InjectionBinding,
    InjectionEvidence,
    InjectionPlan,
    McpServerPatch,
    Surface,
    ToolCallEvent,
)
from garak.injectors.base import Injector

# MiMCP's recording cap when the environment does not set one; a recording
# count at the cap means calls were dropped, so coverage is incomplete
MIMCP_DEFAULT_MAX_RECORDED_CALLS = 1000

# plan operations MiMCP can express, and the fields each carries beyond
# the shared "op" and "tool"
MIMCP_OPERATIONS = {
    "append_text": {"text"},
    "replace_text": {"text"},
    "patch_structured": {"patch", "sync_text"},
    "override": {"response"},
}


def _max_recorded_calls() -> int:
    return int(
        os.getenv("MIMCP_MAX_RECORDED_CALLS", str(MIMCP_DEFAULT_MAX_RECORDED_CALLS))
    )


def _deep_merge(base: dict, patch: dict) -> dict:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _overlays(operations) -> list[dict]:
    """Translate plan operations into MiMCP tool overlay entries.

    Operations on the same tool merge: text operations become the inject
    template, patch_structured operations deep-merge into one structured
    patch, and sync_text turns on text resync. override must stand alone
    on its tool.
    """
    by_tool: dict[str, list[dict]] = {}
    for operation in operations:
        by_tool.setdefault(operation["tool"], []).append(operation)
    overlays = []
    for tool, tool_operations in by_tool.items():
        text_operations = [
            operation
            for operation in tool_operations
            if operation["op"] in ("append_text", "replace_text")
        ]
        patch_operations = [
            operation
            for operation in tool_operations
            if operation["op"] == "patch_structured"
        ]
        overrides = [
            operation for operation in tool_operations if operation["op"] == "override"
        ]
        if overrides:
            if len(tool_operations) > 1:
                raise InvalidInjectionPlanError(
                    f"override must stand alone on tool {tool!r}"
                )
            behavior = {"type": "override", "response": overrides[0]["response"]}
        else:
            if len(text_operations) > 1:
                raise InvalidInjectionPlanError(
                    f"at most one text operation may target tool {tool!r}"
                )
            behavior = {}
            if text_operations:
                operation = text_operations[0]
                behavior["template"] = (
                    "{original_text}" + operation["text"]
                    if operation["op"] == "append_text"
                    else operation["text"]
                )
            if patch_operations:
                patch = {}
                for operation in patch_operations:
                    patch = _deep_merge(patch, operation["patch"])
                behavior["structured_patch"] = patch
                if any(operation.get("sync_text") for operation in patch_operations):
                    behavior["resync_text"] = True
            if not behavior:
                raise InvalidInjectionPlanError(
                    f"no expressible operation for tool {tool!r}"
                )
            behavior["type"] = "inject"
        overlays.append({"name": tool, "behavior": behavior})
    return overlays


class MiMCPBinding(InjectionBinding):
    """One MiMCP session bound to one generation.

    The session carries the plan's tool overlay and relays every tool call
    to the upstream server named by the surface; ``target_patch`` points
    the target's server label at the session, ``collect_evidence()``
    reads the session's recordings and status, and ``close()`` deletes
    the session.
    """

    def __init__(
        self,
        injector: "MiMCPInjector",
        plan: InjectionPlan,
        surface: Surface,
        execution_id: str,
    ) -> None:
        super().__init__()
        self._injector = injector
        self.execution_id = execution_id
        self._session_id = None
        body = {
            "name": f"{injector.session_prefix}-{execution_id}",
            "upstream": injector.upstream_config(surface),
            "tools": _overlays(plan.operations),
        }
        created = injector._request("post", "/api/sessions", json=body)
        self._session_id = created["session_id"]
        if injector.advertised_base:
            server_url = injector.advertised_base.rstrip("/") + "/mcp"
        else:
            server_url = created["mcp"]["url"]
        attach = surface.attach or {}
        if attach.get("patch") == garak.channels.PATCH_MCP_SERVER:
            # the bare token passes through as the authorization field
            # value; endpoints that add the Bearer prefix expect this
            self.target_patch = McpServerPatch(
                label=attach.get("label") or surface.name,
                url=server_url,
                headers={"Authorization": self._session_id},
            )

    def collect_evidence(self) -> InjectionEvidence:
        """Read the session's recordings and status into contract evidence."""
        if self._session_id is None:
            raise InjectorError(
                f"binding {self.execution_id} is closed; collect evidence before close()"
            )
        calls = self._injector._request(
            "get", f"/api/sessions/{self._session_id}/calls"
        )
        status = self._injector._request("get", f"/api/sessions/{self._session_id}")
        events = tuple(self._event(call) for call in calls)
        recorded = status.get("call_count", len(calls))
        injected = sum(1 for event in events if event.injected)
        return InjectionEvidence(
            execution_id=self.execution_id,
            delivery=Delivery(
                delivered=injected > 0,
                injected_calls=injected,
                recorded_calls=recorded,
            ),
            coverage=Coverage(
                target_connected=status.get("status") == "connected",
                recording_complete=recorded < _max_recorded_calls(),
                errors=tuple(self.coverage_errors),
            ),
            events=events,
        )

    @staticmethod
    def _event(call: dict) -> ToolCallEvent:
        """Map one MiMCP RecordedCall onto a contract event."""
        behavior = call.get("behavior")
        if behavior == "inject":
            # upstream_response is the body before the rewrite; unset means
            # the call was a passthrough despite the overlay
            injected = call.get("upstream_response") is not None
        else:
            injected = behavior == "override"
        return ToolCallEvent(
            event_id=call.get("call_id", ""),
            tool=call.get("tool", ""),
            arguments=call.get("arguments") or {},
            outcome=call.get("status", "error"),
            result=call.get("response"),
            original_result=call.get("upstream_response"),
            injected=injected,
            source="mimcp",
        )

    def _close(self) -> None:
        if self._session_id is None:
            return
        try:
            self._injector._request(
                "delete", f"/api/sessions/{self._session_id}", ok=False
            )
        except InjectorError as e:
            # an expired or unreachable session must not fail the run
            message = str(e)
            logging.warning("MiMCP session teardown failed: %s", message)
            self.coverage_errors.append(message)
        finally:
            self._session_id = None


class MiMCPInjector(Injector):
    """Injector that routes a target's MCP traffic through a MiMCP proxy.

    Surfaces come from the injector config: each names a channel (always
    ``tool_result`` here), the upstream URL MiMCP proxies, and an
    optional ``attach`` patch telling the generator which server label
    to route through the session. ``bind()`` creates a token-routed
    MiMCP session carrying the plan's tool overlay and returns a binding
    that relays every tool call to the upstream, splices the armed
    payloads into matching tool results, and records every call. The
    injector itself holds no per-execution state.
    """

    doc_uri = "https://github.com/ABeltramo/mcp-explorer"
    active = True
    channels = frozenset({garak.channels.TOOL_RESULT})

    DEFAULT_PARAMS = {
        "host": "http://127.0.0.1:8000",
        "session_prefix": "garak",
        "timeout": 30.0,
        "advertised_base": None,
        "surfaces": {},
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._configured_surfaces = tuple(
            self._surface_from_config(name, entry)
            for name, entry in (self.surfaces or {}).items()
        )
        self._tools_prefetched = False

    def _surface_from_config(self, name: str, entry: dict) -> Surface:
        if not isinstance(entry, dict):
            raise InvalidInjectionPlanError(
                f"surface {name!r} in {self.fullname} config must be a mapping"
            )
        channel = entry.get("channel")
        if channel != garak.channels.TOOL_RESULT:
            raise InvalidInjectionPlanError(
                f"surface {name!r} in {self.fullname} config names channel "
                f"{channel!r}; MiMCP only proxies {garak.channels.TOOL_RESULT}"
            )
        attach = entry.get("attach")
        if attach is not None:
            if not isinstance(attach, dict) or attach.get("patch") not in (
                None,
                garak.channels.PATCH_MCP_SERVER,
            ):
                raise InvalidInjectionPlanError(
                    f"surface {name!r} in {self.fullname} config attaches "
                    f"{attach!r}; MiMCP can only attach "
                    f"{garak.channels.PATCH_MCP_SERVER}"
                )
        return Surface(
            name=name,
            channel=channel,
            upstream={"url": entry.get("upstream")},
            attach=attach,
        )

    def offered_surfaces(self) -> tuple[Surface, ...]:
        """Return the configured surfaces, with tools from preflight.

        The tool list comes from the upstream ``tools/list`` through a
        short-lived session; when the proxy is unreachable the surface
        stays in the list with no tools, so a run with one surface per
        channel still works.
        """
        if not self._tools_prefetched:
            for surface in self._configured_surfaces:
                tools = self._preflight_tools(surface)
                self._replace_surface_tools(surface, tools)
            self._tools_prefetched = True
        return self._configured_surfaces

    def _replace_surface_tools(self, surface: Surface, tools: tuple[str, ...]) -> None:
        # surfaces are frozen; rebuild the tuple entry with the tools
        replaced = Surface(
            name=surface.name,
            channel=surface.channel,
            tools=tools,
            upstream=surface.upstream,
            attach=surface.attach,
        )
        self._configured_surfaces = tuple(
            replaced if entry.name == surface.name else entry
            for entry in self._configured_surfaces
        )

    def _preflight_tools(self, surface: Surface) -> tuple[str, ...]:
        """List the upstream tools through a short-lived proxy session."""
        try:
            self.upstream_config(surface)
            created = self._request(
                "post",
                "/api/sessions",
                json={
                    "name": f"{self.session_prefix}-preflight-{surface.name}",
                    "upstream": self.upstream_config(surface),
                    "tools": [],
                },
            )
            session_id = created["session_id"]
            try:
                tools = self._request("get", f"/api/sessions/{session_id}/tools")
            finally:
                self._request("delete", f"/api/sessions/{session_id}", ok=False)
            return tuple(tool.get("name", "") for tool in tools)
        except InjectorError as e:
            logging.debug(
                "MiMCP preflight could not list tools for surface %s: %s",
                surface.name,
                e,
            )
            return ()

    def validate(self, plan: InjectionPlan, surface: Surface) -> None:
        """Reject plans MiMCP cannot express on the surface."""
        super().validate(plan, surface)
        self.upstream_config(surface)
        for index, operation in enumerate(plan.operations):
            if not isinstance(operation, dict):
                raise InvalidInjectionPlanError(
                    f"operation {index} is not a mapping: {operation!r}"
                )
            op = operation.get("op")
            if op not in MIMCP_OPERATIONS:
                raise InvalidInjectionPlanError(
                    f"MiMCP cannot express operation {op!r}; it supports "
                    f"{sorted(MIMCP_OPERATIONS)}"
                )
            if not operation.get("tool"):
                raise InvalidInjectionPlanError(
                    f"operation {index} ({op}) names no tool"
                )
            allowed = MIMCP_OPERATIONS[op] | {"op", "tool"}
            unknown = set(operation) - allowed
            if unknown:
                raise InvalidInjectionPlanError(
                    f"operation {index} ({op}) carries unknown fields "
                    f"{sorted(unknown)}; allowed are {sorted(allowed)}"
                )
            required = {
                "append_text": "text",
                "replace_text": "text",
                "patch_structured": "patch",
                "override": "response",
            }[op]
            if operation.get(required) is None:
                raise InvalidInjectionPlanError(
                    f"operation {index} ({op}) is missing its {required}"
                )
        # merging rules: reject combinations the overlay cannot express
        _overlays(plan.operations)

    @staticmethod
    def upstream_config(surface: Surface) -> dict:
        """Build the MiMCP upstream config from the surface's endpoint data."""
        upstream = surface.upstream or {}
        if not upstream.get("url"):
            raise InvalidInjectionPlanError(
                f"surface {surface.name!r} carries no upstream URL for MiMCP "
                "to proxy; set it in the injector config"
            )
        return {"url": upstream["url"]}

    def bind(
        self, plan: InjectionPlan, surface: Surface, execution_id: str
    ) -> MiMCPBinding:
        """Occupy the surface for one execution and return its binding."""
        return MiMCPBinding(self, plan, surface, execution_id)

    def _request(self, method: str, path: str, ok: bool = True, **kwargs) -> dict:
        """One REST call against the MiMCP control plane, errors wrapped."""
        try:
            response = httpx.request(
                method, f"{self.host}{path}", timeout=self.timeout, **kwargs
            )
            if ok:
                response.raise_for_status()
        except httpx.HTTPError as e:
            raise InjectorError(f"MiMCP request {method} {path} failed: {e}") from e
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()
