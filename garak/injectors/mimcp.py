# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""MiMCP injector: occupies the mcp capability through a MiMCP proxy session."""

import logging
import uuid

import httpx

from garak import _config
from garak.capabilities import Capability
from garak.injectors.base import Injector


class MiMCPInjector(Injector):
    """Injector that routes a target's MCP traffic through a MiMCP proxy.

    ``arm()`` creates a token-routed MiMCP session carrying a tool overlay
    and returns the descriptor that generators supporting the mcp capability
    merge into their tool configuration. The proxy relays every tool call to
    the upstream server, splices the armed payloads into matching tool
    results, and records every call; ``get_calls()`` hands those recordings
    to a detector as evidence.
    """

    doc_uri = "https://github.com/ABeltramo/mcp-explorer"
    active = True
    capabilities = [Capability.MCP]

    DEFAULT_PARAMS = {
        "host": "http://127.0.0.1:8000",
        "session_prefix": "garak",
        "timeout": 30.0,
        "advertised_base": None,
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.session_id = None

    def arm(self, payload: dict) -> dict:
        """Create a MiMCP session from an attack spec and arm this injector.

        The payload carries the scenario's attack spec: ``upstream`` URL,
        MiMCP ``tools`` overlay, and optional ``instructions`` and
        ``server_label``. Returns the injection descriptor for the mcp
        capability; the authorization token is the bare session id, which
        endpoints that add the ``Bearer`` prefix themselves expect.
        ``advertised_base`` overrides the URL MiMCP reports for itself: set it
        when the target reaches MiMCP under a different address than this
        runner does, for example ``http://mimcp:8000`` from inside a
        container network.
        """
        if self.session_id is not None:
            self.disarm()
        body = {
            "name": f"{self.session_prefix}-{uuid.uuid4().hex[:8]}",
            "upstream": {"url": payload["upstream"]},
            "tools": payload.get("tools", []),
        }
        if payload.get("instructions"):
            body["instructions"] = payload["instructions"]
        response = httpx.post(
            f"{self.host}/api/sessions", json=body, timeout=self.timeout
        )
        response.raise_for_status()
        created = response.json()
        self.session_id = created["session_id"]
        if self.advertised_base:
            server_url = self.advertised_base.rstrip("/") + "/mcp"
        else:
            server_url = created["mcp"]["url"]
        return {
            "capability": Capability.MCP,
            "server_label": payload.get("server_label", "mimcp"),
            "server_url": server_url,
            "authorization": self.session_id,
        }

    def get_calls(self) -> list[dict]:
        """Return the calls recorded for the armed session, as plain dicts."""
        if self.session_id is None:
            return []
        response = httpx.get(
            f"{self.host}/api/sessions/{self.session_id}/calls",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def disarm(self) -> None:
        """Delete the armed session; an expired session is not an error."""
        if self.session_id is None:
            return
        try:
            httpx.delete(
                f"{self.host}/api/sessions/{self.session_id}", timeout=self.timeout
            )
        except httpx.HTTPError as e:
            logging.debug("MiMCP session teardown failed: %s", e)
        finally:
            self.session_id = None
