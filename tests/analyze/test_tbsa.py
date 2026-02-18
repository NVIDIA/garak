# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
from pathlib import Path
import tempfile

import pytest

import garak.analyze.tbsa

BASE_DIGEST = {
    "meta": {
        "garak_version": "0.00.0.pre0",
    },
    "eval": {
        "ansiescape": {
            "ansiescape.AnsiRaw": {
                "_summary": {"probe_tier": 1},
                "ansiescape.AnsiRaw": {
                    "detector_name": "ansiescape.ansiRaw",
                    "absolute_score": 0.0,
                    "absolute_defcon": 1,
                    "relative_score": 0.0,
                    "relative_defcon": 1,
                },
            },
        },
        "topic": {
            "topic.WordnetControversial": {
                "_summary": {
                    "probe_name": "topic.WordnetControversial",
                    "probe_score": 0.0,
                    "probe_severity": 1,
                    "probe_descr": "Ask model to respond on a set on controversial topics.",
                    "probe_tier": 2,
                    "probe_tags": [
                        "avid-effect:security:S0301",
                        "owasp:llm10",
                        "quality:Security:Confidentiality",
                    ],
                },
                "mitigation.MitigationBypass": {
                    "detector_name": "mitigation.MitigationBypass",
                    "detector_descr": "Detect if a string response does not contain a mitigation message.",
                    "absolute_score": 0.0,
                    "absolute_defcon": 1,
                    "absolute_comment": "immediate risk (complete failure)",
                    "relative_score": -1.9763849847943522,
                    "relative_defcon": 1,
                    "relative_comment": "critical risk",
                    "detector_defcon": 1,
                    "calibration_used": True,
                },
            },
        },
    },
}


def test_tbsa_runs():
    garak.analyze.tbsa.digest_to_tbsa(BASE_DIGEST)


def test_tbsa_value():
    tbsa, hash, pd_count = garak.analyze.tbsa.digest_to_tbsa(BASE_DIGEST)
    assert tbsa == 1.0, "weighted mean of T1 1.0 and T2 1.0 should be 1.0"


def test_tbsa_value_t2_OK():
    t2_ok_digest = BASE_DIGEST
    t2_ok_digest["eval"]["topic"]["topic.WordnetControversial"][
        "mitigation.MitigationBypass"
    ]["relative_defcon"] = 5
    tbsa, hash, pd_count = garak.analyze.tbsa.digest_to_tbsa(t2_ok_digest)
    assert tbsa == 2.3, "weighted avg (1,2) of 1 and 5 is 2.3333, truncated to 2.3"


def test_hash_varies():
    _, base_hash, __ = garak.analyze.tbsa.digest_to_tbsa(BASE_DIGEST)
    altered_version_digest = BASE_DIGEST
    altered_version_digest["meta"]["garak_version"] = "1.2.3.4"
    _, altered_version_hash, __ = garak.analyze.tbsa.digest_to_tbsa(
        altered_version_digest
    )
    assert (
        altered_version_hash != base_hash
    ), "altering version must yield change in pdver hash"
    altered_probes_digest = BASE_DIGEST
    del altered_probes_digest["eval"]["topic"]
    _, altered_probes_hash, __ = garak.analyze.tbsa.digest_to_tbsa(
        altered_version_digest
    )
    assert (
        altered_probes_hash != base_hash
    ), "altering probe selection must yield change in pdver hash"


@pytest.fixture
def tbsa_json_filenames(request) -> None:
    with tempfile.NamedTemporaryFile(mode="wb+", delete=False) as nil_outfile:
        nil_outfile.close()

    with tempfile.NamedTemporaryFile(mode="wb+", delete=False) as one_outfile:
        one_outfile.close()

    def remove_tbsa_json():
        with contextlib.suppress(FileNotFoundError, PermissionError):
            Path(nil_outfile.name).unlink()
            Path(one_outfile.name).unlink()

    request.addfinalizer(remove_tbsa_json)

    return nil_outfile.name, one_outfile.name


def test_stable_hash_different_content(tbsa_json_filenames):
    cli_args_0 = f"-r tests/_assets/analyze/tbsa_digest_0.json -j {tbsa_json_filenames[0]} -q".split()
    cli_args_1 = f"-r tests/_assets/analyze/tbsa_digest_1.json -j {tbsa_json_filenames[1]} -q".split()
    garak.analyze.tbsa.main(cli_args_0)
    garak.analyze.tbsa.main(cli_args_1)

    with open(tbsa_json_filenames[0], "r", encoding="utf-8") as f_nil:
        nil = json.load(f_nil)
        f_nil.close()
    with open(tbsa_json_filenames[1], "r", encoding="utf-8") as f_one:
        one = json.load(f_one)
        f_one.close()

    assert (
        nil["version_probe_hash"] == one["version_probe_hash"]
    ), "hash must be stable across identical probe/detector request inventories"


round_values = {
    (2, 2.0),
    (1.05, 1.1),
    (1.0937129300118624, 1.1),
    (2.15, 2.2),
    (4.99999, 5.0),
    (0, 1.0),
    (-555, 1.0),
    (999, 5.0),
    (5.05, 5.0),
}


@pytest.mark.parametrize("raw,rounded", round_values)
def test_tbsa_rounding(raw, rounded):
    assert garak.analyze.tbsa.round_final_tbsa(raw) == rounded
