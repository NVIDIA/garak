# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""A2A (Agent-to-Agent) Generator

Generator module for probing agents exposing the Agent-to-Agent protocol over JSON-RPC.
"""

import logging
import os
import time
import uuid
from typing import List, Union

import backoff
import requests

from garak import _config
from garak.attempt import Conversation, Message
from garak.exception import RateLimitHit
from garak.generators.base import Generator

logger = logging.getLogger(__name__)

RPC_METHOD_NOT_FOUND = -32601
DIALECTS = ("auto", "v03", "v02")
PENDING_TASK_STATES = {"submitted", "working"}
TASK_POLL_INTERVAL = 1


class A2AGenerator(Generator):
    """Generic Generator for Agent-to-Agent (A2A) protocol endpoints.

    Communicates with agents implementing task-based message exchange over JSON-RPC 2.0.
    Natively negotiates between:
    - Spec 0.3+ (`message/send` with `kind: "text"`)
    - Spec 0.2 (`tasks/send` with `type: "text"`)

    Automatically falls back from 0.3 to 0.2 when encountering error code -32601 (Method not found).

    Each call opens a new A2A context. A2A clients can only send ``user`` messages,
    so any system or earlier turns in the probe ``Conversation`` are sent as
    role-labelled text parts ahead of the final user prompt.
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "name": None,
        "uri": None,
        "api_key": None,
        "api_key_header": "X-API-Key",
        "auth_token": None,
        "request_timeout": 30,
        "verify_ssl": True,
        "dialect": "auto",
    }

    _supported_params = (
        "name",
        "uri",
        "api_key",
        "api_key_header",
        "auth_token",
        "key_env_var",
        "request_timeout",
        "verify_ssl",
        "dialect",
        "max_tokens",
        "temperature",
        "top_k",
        "context_len",
        "skip_seq_start",
        "skip_seq_end",
    )

    ENV_VAR = "A2A_API_KEY"
    generator_family_name = "A2A"

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root=config_root)
        if not self.uri and self.name and self.name.startswith(("http://", "https://")):
            self.uri = self.name
        if not self.uri:
            raise ValueError(
                "No A2A endpoint URI definition found in either config or --target_name. Please specify one."
            )
        if not self.name:
            self.name = self.uri
            self.fullname = f"{self.generator_family_name}:{self.name}"
        if self.dialect not in DIALECTS:
            raise ValueError(
                f"Unknown A2A dialect '{self.dialect}', expected one of {DIALECTS}"
            )

    def _validate_env_var(self):
        """Auth is optional for A2A endpoints; only load a key from the environment when one is requested.

        Env based auth is considered requested when ``key_env_var`` is set to something
        other than the default, or when the default ``A2A_API_KEY`` is present.
        """
        if self.api_key is not None or self.auth_token is not None:
            return
        if self.key_env_var != self.ENV_VAR or os.getenv(self.key_env_var) is not None:
            super()._validate_env_var()

    def _build_headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.api_key:
            headers[self.api_key_header] = self.api_key
        return headers

    @staticmethod
    def _conversation_texts(prompt: Conversation) -> List[tuple]:
        """Flatten a Conversation into (role, text) pairs, ending in the user prompt."""
        if not prompt.turns or prompt.turns[-1].role != "user":
            raise ValueError(
                "A2AGenerator requires a Conversation ending in a user turn"
            )
        texts = []
        for idx, turn in enumerate(prompt.turns):
            text = turn.content.text or ""
            if idx < len(prompt.turns) - 1:
                text = f"{turn.role.capitalize()}: {text}"
            texts.append((turn.role, text))
        return texts

    def _build_payload(self, dialect: str, prompt: Conversation) -> dict:
        part_type_key = "kind" if dialect == "v03" else "type"
        parts = [
            {part_type_key: "text", "text": text, "metadata": {"role": role}}
            for role, text in self._conversation_texts(prompt)
        ]
        message = {"role": "user", "parts": parts}
        if dialect == "v03":
            message |= {"kind": "message", "messageId": str(uuid.uuid4())}
            method = "message/send"
            params = {"message": message, "configuration": {"blocking": True}}
        else:
            method = "tasks/send"
            params = {"id": str(uuid.uuid4()), "message": message}
        return {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
        }

    @staticmethod
    def _parts_text(parts) -> List[str]:
        if not isinstance(parts, list):
            return []
        return [
            str(part["text"])
            for part in parts
            if isinstance(part, dict) and "text" in part
        ]

    def _extract_response_text(self, result) -> str:
        if not isinstance(result, dict):
            return str(result) if result is not None else ""

        # Message response, or a message embedded in the task result
        texts = self._parts_text(result.get("parts"))
        if not texts and isinstance(result.get("message"), dict):
            texts = self._parts_text(result["message"].get("parts"))
        if texts:
            return "\n".join(texts)

        # Task artifacts
        artifacts = result.get("artifacts")
        if isinstance(artifacts, list):
            for art in artifacts:
                if isinstance(art, dict):
                    texts.extend(self._parts_text(art.get("parts")))
            if texts:
                return "\n".join(texts)

        # Task status message, e.g. input-required or failed
        status = result.get("status")
        if isinstance(status, dict) and isinstance(status.get("message"), dict):
            texts = self._parts_text(status["message"].get("parts"))
            if texts:
                return "\n".join(texts)

        return str(result)

    def _post(self, payload: dict) -> dict:
        resp = requests.post(
            self.uri,
            json=payload,
            headers=self._build_headers(),
            timeout=self.request_timeout,
            verify=self.verify_ssl,
        )
        if resp.status_code == 429:
            raise RateLimitHit(f"A2A rate limited: {resp.reason}, uri: {self.uri}")
        resp.raise_for_status()
        return resp.json()

    def _await_task(self, data: dict) -> dict:
        """Poll ``tasks/get`` until a task returned by the agent leaves a pending state."""
        deadline = time.monotonic() + self.request_timeout
        while True:
            result = data.get("result")
            if not (
                isinstance(result, dict)
                and result.get("status", {}).get("state") in PENDING_TASK_STATES
            ):
                return data
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"A2A task {result.get('id')} still {result['status']['state']} after {self.request_timeout}s"
                )
            time.sleep(TASK_POLL_INTERVAL)
            data = self._post(
                {
                    "jsonrpc": "2.0",
                    "id": str(uuid.uuid4()),
                    "method": "tasks/get",
                    "params": {"id": result["id"]},
                }
            )

    @backoff.on_exception(backoff.fibo, RateLimitHit, max_value=70)
    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        current_dialect = "v02" if self.dialect == "v02" else "v03"

        try:
            data = self._post(self._build_payload(current_dialect, prompt))

            # Handle automatic fallback from 0.3 to 0.2 if method not found
            if (
                self.dialect == "auto"
                and isinstance(data.get("error"), dict)
                and data["error"].get("code") == RPC_METHOD_NOT_FOUND
            ):
                logger.info(
                    "A2A method message/send returned -32601; falling back to tasks/send (0.2)"
                )
                current_dialect = "v02"
                data = self._post(self._build_payload(current_dialect, prompt))
            if self.dialect == "auto" and data.get("error") is None:
                self.dialect = current_dialect
            data = self._await_task(data)

        except requests.RequestException as exc:
            logger.error("Failed to query A2A agent at %s: %s", self.uri, exc)
            raise ConnectionError(f"A2A communication failure: {exc}") from exc

        # agents may relay an upstream model rate limit as an internal error
        error = data.get("error")
        if isinstance(error, dict) and "429" in str(error.get("message", "")):
            raise RateLimitHit(f"A2A upstream rate limited: {error}, uri: {self.uri}")

        # JSON-RPC errors are protocol failures, not model output
        if error is not None:
            logger.warning(
                "A2A agent at %s returned error: %s", self.uri, data["error"]
            )
            return [None]

        return [Message(text=self._extract_response_text(data.get("result")))]


DEFAULT_CLASS = "A2AGenerator"
