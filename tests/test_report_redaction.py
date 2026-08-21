# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Secrets in run setup must not be persisted into reports."""

import json
from pathlib import Path

from garak import _config
import garak.command as command


def test_redact_sensitive_config_nested_api_key():
    secret = "sk-super-secret-test-key"
    original = {
        "openai": {
            "OpenAIGenerator": {"api_key": secret, "name": "gpt-4o-mini"},
            "headers": {"Authorization": f"Bearer {secret}"},
        },
        "target_type": "openai",
    }
    redacted = _config._redact_sensitive_config(original)
    assert (
        redacted["openai"]["OpenAIGenerator"]["api_key"]
        == _config.REDACTED_CONFIG_VALUE
    )
    assert (
        redacted["openai"]["headers"]["Authorization"] == _config.REDACTED_CONFIG_VALUE
    )
    assert redacted["openai"]["OpenAIGenerator"]["name"] == "gpt-4o-mini"
    assert redacted["target_type"] == "openai"
    assert (
        original["openai"]["OpenAIGenerator"]["api_key"] == secret
    ), "redaction must not mutate the live config object"


def test_redact_sensitive_config_hyphenated_and_suffixed_keys():
    secret = "n0t-a-real-secret"
    original = {
        "X-API-Key": secret,
        "client_key_passphrase": secret,
        "judge_api_token": secret,
        "key_env_var": "OPENAI_API_KEY",
        "client_key": "/tmp/client.pem",
    }
    redacted = _config._redact_sensitive_config(original)
    assert redacted["X-API-Key"] == _config.REDACTED_CONFIG_VALUE
    assert redacted["client_key_passphrase"] == _config.REDACTED_CONFIG_VALUE
    assert redacted["judge_api_token"] == _config.REDACTED_CONFIG_VALUE
    assert (
        redacted["key_env_var"] == "OPENAI_API_KEY"
    ), "env var *name* is not a secret and must stay readable"
    assert (
        redacted["client_key"] == "/tmp/client.pem"
    ), "client_key is a cert path, not a secret value"


def test_start_run_includes_plugin_trees_and_redacts_secrets(tmp_path):
    secret = "sk-must-not-appear-in-report"
    _config.load_base_config()
    _config.system.lite = False
    _config.reporting.report_dir = str(tmp_path)
    _config.reporting.report_prefix = "secret_redact"
    # YAML / --generator_options land in the same defaultdict trees used at runtime
    _config.plugins.generators["openai"]["OpenAIGenerator"]["api_key"] = secret
    _config.plugins.generators["openai"]["OpenAIGenerator"]["name"] = "gpt-4o-mini"
    _config.plugins.generators["rest"]["RestGenerator"]["headers"] = {
        "Authorization": f"Bearer {secret}"
    }
    _config.transient.starttime_iso = "2026-08-21T00:00:00"

    command.start_run()
    report_filename = _config.transient.report_filename
    _config.transient.reportfile.close()

    report_text = Path(report_filename).read_text(encoding="utf-8")
    assert (
        secret not in report_text
    ), "api_key from plugin config must not be written into the JSONL report"
    setup = json.loads(report_text.splitlines()[0])
    assert setup["entry_type"] == "start_run setup"
    assert (
        "plugins.generators" in setup
    ), "defaultdict plugin trees must be recorded in start_run setup"
    generators = setup["plugins.generators"]
    assert generators["openai"]["OpenAIGenerator"]["name"] == "gpt-4o-mini"
    assert (
        generators["openai"]["OpenAIGenerator"]["api_key"]
        == _config.REDACTED_CONFIG_VALUE
    )
    assert (
        generators["rest"]["RestGenerator"]["headers"]["Authorization"]
        == _config.REDACTED_CONFIG_VALUE
    )
    assert (
        _config.plugins.generators["openai"]["OpenAIGenerator"]["api_key"] == secret
    ), "live plugin config must keep the real key for the generator"
