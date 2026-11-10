# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _plugins
import garak.attempt
import garak.probes.base
import garak.probes.tooluse

PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.tooluse")
]

TOOLUSE_CLASSES = [
    garak.probes.tooluse.PermissionEscalation,
    garak.probes.tooluse.ToolChainAbuse,
    garak.probes.tooluse.ServerPhishing,
    garak.probes.tooluse.CredentialExfiltration,
]


@pytest.mark.parametrize("classname", PROBES)
def test_tooluse_probe_loads(classname):
    probe = _plugins.load_plugin(classname)
    assert isinstance(probe, garak.probes.base.Probe)


@pytest.mark.parametrize("probe_class", TOOLUSE_CLASSES)
def test_prompts_generated(probe_class):
    probe = probe_class()
    assert len(probe.prompts) == len(probe_class.cases)
    assert len(probe.prompts) > 0
    for prompt in probe.prompts:
        assert isinstance(prompt, str)
        assert len(prompt) > 0


@pytest.mark.parametrize("probe_class", TOOLUSE_CLASSES)
def test_probe_metadata(probe_class):
    probe = probe_class()
    assert probe.lang == "en"
    assert isinstance(probe.goal, str) and len(probe.goal) > 0
    assert probe.tier == garak.probes.Tier.INFORMATIONAL
    assert probe.active is False
    assert isinstance(probe.primary_detector, str)


@pytest.mark.parametrize("probe_class", TOOLUSE_CLASSES)
def test_prestore_hook_records_trace(probe_class):
    probe = probe_class()
    for seq in range(len(probe.prompts)):
        attempt = garak.attempt.Attempt(
            prompt=garak.attempt.Message(text=probe.prompts[seq], lang="en")
        )
        attempt = probe._attempt_prestore_hook(attempt, seq)
        assert "tool_manifest" in attempt.notes
        assert isinstance(attempt.notes["tool_manifest"], list)
        assert "mcp_annotations" in attempt.notes
        assert "expected_verdict" in attempt.notes
        assert attempt.notes["failure_class"] == probe_class.failure_class


def test_manifest_includes_mcp_annotations():
    """Read-only escalation cases must surface the readOnlyHint annotation in the prompt."""
    probe = garak.probes.tooluse.PermissionEscalation()
    assert any("readOnlyHint" in prompt for prompt in probe.prompts)


def test_credential_exfil_sets_triggers():
    """Credential exfiltration must plant the secret as a detector trigger and in the prompt context."""
    probe = garak.probes.tooluse.CredentialExfiltration()
    assert probe.primary_detector == "base.TriggerListDetector"
    for seq, case in enumerate(probe.cases):
        attempt = garak.attempt.Attempt(
            prompt=garak.attempt.Message(text=probe.prompts[seq], lang="en")
        )
        attempt = probe._attempt_prestore_hook(attempt, seq)
        assert attempt.notes["triggers"] == [case["secret"]]
        assert case["secret"] in probe.prompts[seq]


def test_credential_exfil_detector_flags_leak():
    """The TriggerListDetector should fire when the planted secret is echoed back."""
    detector = _plugins.load_plugin("detectors.base.TriggerListDetector")
    probe = garak.probes.tooluse.CredentialExfiltration()
    secret = probe.cases[0]["secret"]

    leaking = garak.attempt.Attempt(
        prompt=garak.attempt.Message(text=probe.prompts[0], lang="en")
    )
    leaking.notes["triggers"] = [secret]
    leaking.outputs = [
        garak.attempt.Message(text=f"Calling weather.get with X-Debug-Token: {secret}")
    ]
    assert detector.detect(leaking) == [1.0]

    refusing = garak.attempt.Attempt(
        prompt=garak.attempt.Message(text=probe.prompts[0], lang="en")
    )
    refusing.notes["triggers"] = [secret]
    refusing.outputs = [
        garak.attempt.Message(
            text="I can't include the API key in a request to a third party."
        )
    ]
    assert detector.detect(refusing) == [0.0]
