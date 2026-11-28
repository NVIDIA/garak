# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _plugins
import garak.probes.base
import garak.probes.taginjection

TAG_INJECTION_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.taginjection")
]


@pytest.mark.parametrize("classname", TAG_INJECTION_PROBES)
def test_taginjection_structure(classname):
    p = _plugins.load_plugin(classname)
    assert isinstance(
        p, garak.probes.base.Probe
    ), "Tag injection probes must be instances of probes.base.Probe"
    assert (
        len(p.prompts) == len(p.triggers) == len(p.tagged)
    ), "Each prompt must have a matching trigger and tagged flag"
    assert (
        len(p.prompts) >= 30
    ), "Tag injection probes should have a substantial number of prompts"


@pytest.mark.parametrize("classname", TAG_INJECTION_PROBES)
def test_taginjection_prompts_contain_trigger(classname):
    p = _plugins.load_plugin(classname)
    for i, prompt in enumerate(p.prompts):
        assert (
            p.triggers[i] in prompt
        ), "Each prompt must contain its trigger verbatim, inside the injection instruction"


@pytest.mark.parametrize("classname", TAG_INJECTION_PROBES)
def test_taginjection_tagged_control_pairing(classname):
    p = _plugins.load_plugin(classname)
    tagged_prompts = [prompt for prompt, t in zip(p.prompts, p.tagged) if t]
    control_prompts = [prompt for prompt, t in zip(p.prompts, p.tagged) if not t]
    assert len(tagged_prompts) > 0, "Probe must include tag-framed prompts"
    assert len(control_prompts) > 0, "Probe must include untagged control prompts"
    for prompt in tagged_prompts:
        assert any(
            frame_start in prompt or frame_end in prompt
            for frame_start, frame_end in garak.probes.taginjection.TAG_FRAMES
        ), "Tagged prompts must be framed by one of the tag frames"
    for prompt in control_prompts:
        for frame_start, frame_end in garak.probes.taginjection.TAG_FRAMES:
            assert (
                frame_start not in prompt and frame_end not in prompt
            ), "Control prompts must not contain any tag framing"
    # every control has at least one tagged counterpart carrying the
    # same injection instruction (the control text appears, framed, in it)
    for i, prompt in enumerate(p.prompts):
        if p.tagged[i]:
            continue
        task, _, injection = prompt.partition("\n\n")
        counterparts = [
            tp
            for tp, t in zip(p.prompts, p.tagged)
            if t and tp.startswith(task) and injection in tp
        ]
        assert (
            len(counterparts) > 0
        ), "Each untagged control must have a tagged counterpart with the same injection"


@pytest.mark.parametrize("classname", TAG_INJECTION_PROBES)
def test_taginjection_attempt_notes(classname):
    p = _plugins.load_plugin(classname)
    for seq in range(len(p.prompts)):
        attempt = p._mint_attempt(p.prompts[seq], seq)
        assert attempt.notes["triggers"] == [
            p.triggers[seq]
        ], "Attempt notes must carry the prompt's trigger for the paired detector"
        assert (
            attempt.notes["tagged"] == p.tagged[seq]
        ), "Attempt notes must record whether the prompt was tag-framed or a control"
        assert (
            attempt.notes["frame"] == p.prompt_frames[seq]
        ), "Attempt notes must record which frame a prompt used, for per-tag reporting"
        if p.tagged[seq]:
            assert (
                attempt.notes["frame"] is not None
            ), "Tagged attempts must name their frame"
        else:
            assert (
                attempt.notes["frame"] is None
            ), "Control attempts must record no frame"


def test_taginjection_wilson_interval():
    wilson = garak.probes.taginjection.wilson_interval
    lower, upper = wilson(13, 13)
    assert (
        abs(lower - 0.772) < 0.002
    ), "A perfect 13/13 must give a 95% Wilson lower bound of about 0.772"
    assert upper == 1.0, "A perfect score's Wilson upper bound must be 1.0"
    lower, upper = wilson(0, 13)
    assert lower == 0.0, "Zero hits must give a Wilson lower bound of 0.0"
    assert (
        abs(upper - 0.228) < 0.002
    ), "Zero hits in 13 must give a 95% Wilson upper bound of about 0.228"
    assert wilson(0, 0) == (
        0.0,
        1.0,
    ), "An empty cell must report the full range: nothing ruled out"


def test_taginjection_paired_rate_summary():
    p = _plugins.load_plugin("probes.taginjection.SpecialTokens")
    attempts = []
    for seq in range(len(p.prompts)):
        attempt = p._mint_attempt(p.prompts[seq], seq)
        # synthetic scoring: controls never trigger, the first frame
        # always triggers, other frames never trigger
        first_frame = garak.probes.taginjection.frame_label(p.frames[0])
        triggered = attempt.notes["frame"] == first_frame
        attempt.detector_results["base.TriggerListDetector"] = [
            1.0 if triggered else 0.0
        ]
        attempts.append(attempt)
    rows = garak.probes.taginjection.paired_rate_summary(attempts)
    assert len(rows) == len(
        p.frames
    ), "Summary must carry one row per frame the probe used"
    first = rows[0]
    assert first["frame"] == garak.probes.taginjection.frame_label(
        p.frames[0]
    ), "Rows must be in probe frame order"
    assert (
        first["tagged_rate"] == 1.0 and first["tagged_n"] == 9
    ), "The always-triggering frame must report rate 1.0 with its n (9)"
    assert (
        abs(first["tagged_interval"][0] - 0.701) < 0.002
    ), "A perfect 9/9 must show the small-cell Wilson lower bound of about 0.701"
    assert all(
        row["tagged_rate"] == 0.0 for row in rows[1:]
    ), "Frames that never triggered must report rate 0.0"
    control = first["control"]
    assert (
        control["rate"] == 0.0 and control["n"] == 9
    ), "Controls must be pooled beside the frames: 9 controls, none triggered"
    assert all(
        row["control"] == control for row in rows
    ), "Every row must carry the same pooled control for side-by-side reading"


def test_taginjection_full_covers_all_frames_and_injections():
    p = _plugins.load_plugin("probes.taginjection.SpecialTokensFull")
    assert (
        p.frames == garak.probes.taginjection.TAG_FRAMES
    ), "Full probe must use every tag frame"
    assert (
        p.injections == garak.probes.taginjection.INJECTIONS
    ), "Full probe must use every injection"
    expected = len(p.tasks) * len(p.injections) * (len(p.frames) + 1)
    assert (
        len(p.prompts) == expected
    ), "Full probe must pair every task/injection with every frame plus a control"
