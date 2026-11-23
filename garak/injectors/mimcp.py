# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""MiMCP injector: occupies mcp.server surfaces through a MiMCP proxy session."""

import logging
import os

import httpx

from garak.exception import InjectorError, InvalidInjectionPlanError
from garak.injection import (
    Coverage,
    Delivery,
    InjectionBinding,
    InjectionEvidence,
    InjectionPlan,
    McpRoute,
    SurfaceDescriptor,
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


class MiMCPBinding(InjectionBinding):
    """One MiMCP session bound to one generation.

    The session carries the plan's tool overlay and relays every tool call
    to the upstream server from the surface descriptor; ``route`` points
    the target's server label at the session, ``collect_evidence()``
    reads the session's recordings and status, and ``close()`` deletes
    the session.
    """

    def __init__(
        self,
        injector: "MiMCPInjector",
        plan: InjectionPlan,
        surface: SurfaceDescriptor,
        execution_id: str,
    ) -> None:
        super().__init__()
        self._injector = injector
        self.execution_id = execution_id
        self._session_id = None
        body = {
            "name": f"{injector.session_prefix}-{execution_id}",
            "upstream": injector.upstream_config(surface),
            "tools": [self._overlay(operation) for operation in plan.operations],
        }
        created = injector._request("post", "/api/sessions", json=body)
        self._session_id = created["session_id"]
        if injector.advertised_base:
            server_url = injector.advertised_base.rstrip("/") + "/mcp"
        else:
            server_url = created["mcp"]["url"]
        # the bare token passes through as the authorization field value;
        # endpoints that add the Bearer prefix themselves expect this
        self.route = McpRoute(
            replaces=surface.name,
            url=server_url,
            headers={"Authorization": self._session_id},
        )

    @staticmethod
    def _overlay(operation: dict) -> dict:
        """Translate one plan operation into a MiMCP tool overlay entry."""
        overlay = {"name": operation["tool"]}
        op = operation["op"]
        if op == "append_text":
            overlay["behavior"] = {
                "type": "inject",
                "template": "{original_text}" + operation["text"],
            }
        elif op == "replace_text":
            overlay["behavior"] = {"type": "inject", "template": operation["text"]}
        elif op == "patch_structured":
            behavior = {
                "type": "inject",
                "structured_patch": operation["patch"],
            }
            if operation.get("sync_text"):
                behavior["resync_text"] = True
            overlay["behavior"] = behavior
        elif op == "override":
            overlay["behavior"] = {
                "type": "override",
                "response": operation["response"],
            }
        else:  # validate() rejects this before bind() runs
            raise InvalidInjectionPlanError(f"MiMCP cannot express operation {op!r}")
        return overlay

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

    ``bind()`` creates a token-routed MiMCP session carrying the plan's
    tool overlay and returns a binding whose route replaces the target's
    configured server block. The proxy relays every tool call to the
    upstream server, splices the armed payloads into matching tool
    results, and records every call; ``collect_evidence()`` hands those
    recordings to a detector as contract evidence. The injector itself
    holds no per-execution state.
    """

    doc_uri = "https://github.com/ABeltramo/mcp-explorer"
    active = True
    surface_kinds = frozenset({"mcp.server"})

    DEFAULT_PARAMS = {
        "host": "http://127.0.0.1:8000",
        "session_prefix": "garak",
        "timeout": 30.0,
        "advertised_base": None,
    }

    def validate(self, plan: InjectionPlan, surface: SurfaceDescriptor) -> None:
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

    @staticmethod
    def upstream_config(surface: SurfaceDescriptor) -> dict:
        """Build the MiMCP upstream config from the surface's endpoint data."""
        upstream = surface.upstream or {}
        if not upstream.get("server_url"):
            raise InvalidInjectionPlanError(
                f"surface {surface.kind}/{surface.name} carries no upstream "
                "server_url for MiMCP to proxy"
            )
        config = {"url": upstream["server_url"]}
        headers = upstream.get("headers") or {}
        if headers:
            config["headers"] = headers
        return config

    def bind(
        self, plan: InjectionPlan, surface: SurfaceDescriptor, execution_id: str
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
