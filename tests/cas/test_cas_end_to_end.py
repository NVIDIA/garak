"""Exercise context-aware scanning from CLI selection to the emitted digest."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

PROBE = "grandma.GrandmaIntent"
META_INTENT = "M010degrade"
KEY_INTENT = "S003productkeyswin10"
META_DETECTOR = "any.AnyNonspaceOutput"
KEY_DETECTORS = {"productkey.Win5x5", "mitigation.MitigationBypass"}


@pytest.mark.parametrize(
    "meta_selector",
    [
        "intent:M010degrade",
        "intent:M010,-intent:M010blank,-intent:M010rep",
    ],
    ids=["leaf", "category-with-exclusions"],
)
@pytest.mark.parametrize(
    "target,response,key_passes,mitigation_passes,nones",
    [
        ("Single", "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", 0, 0, 0),
        ("Single", "I cannot assist with that request.", 4, 4, 0),
        ("Single", "An ordinary reply without a product key.", 4, 0, 0),
        ("Nones", None, 0, 0, 4),
    ],
    ids=["key-shaped-output", "refusal", "detector-disagreement", "missing-output"],
)
def test_cas_cli_preserves_intent_outcomes(
    tmp_path, meta_selector, target, response, key_passes, mitigation_passes, nones
):
    """Real probes and detectors keep intent routing and counts through reporting."""
    config = {
        "system": {"parallel_attempts": 1, "parallel_requests": 1},
        "run": {
            "seed": 0,
            "generations": 2,
            "soft_probe_prompt_cap": 4,
        },
        "plugins": {
            "generators": {"test": {"Single": {"test_generation_string": response}}}
        },
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    prefix = tmp_path / "cas"
    env = {
        **os.environ,
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "GARAK_LOG_FILE": os.devnull,
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "garak",
            "--config",
            str(config_path),
            "--target_type",
            f"test.{target}",
            "--spec",
            f"probes.{PROBE},intent:{KEY_INTENT},{meta_selector}",
            "--report_prefix",
            str(prefix),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"CAS scan failed:\n{result.stdout}\n{result.stderr}"
    assert "garak run complete" in result.stdout, "CLI must finish the scan"
    report_path = prefix.with_suffix(".report.jsonl")
    records = [
        json.loads(line)
        for line in report_path.read_text(encoding="utf-8").splitlines()
    ]
    attempts = [
        row for row in records if row["entry_type"] == "attempt" and row["status"] == 2
    ]
    assert len(attempts) == 4, "the configured cap must retain two prompts per intent"
    for intent, detectors in [
        (META_INTENT, {META_DETECTOR}),
        (KEY_INTENT, KEY_DETECTORS),
    ]:
        selected = [attempt for attempt in attempts if attempt["intent"] == intent]
        assert len(selected) == 2, "each selected intent must reach the target"
        for attempt in selected:
            assert (
                set(attempt["detector_results"]) == detectors
            ), "only detectors mapped to this intent may score its outputs"
            assert all(
                len(scores) == 2 for scores in attempt["detector_results"].values()
            ), "both generations must be scored"

    evals = [row for row in records if row["entry_type"] == "eval"]
    expected = {
        META_DETECTOR: (META_INTENT, 0),
        "productkey.Win5x5": (KEY_INTENT, key_passes),
        "mitigation.MitigationBypass": (KEY_INTENT, mitigation_passes),
    }
    assert len(evals) == len(expected), "each intent detector must emit one evaluation"
    assert {row["detector"] for row in evals} == set(
        expected
    ), "the report must contain every intent-resolved detector"
    for row in evals:
        intent, passes = expected[row["detector"]]
        counts = {"passed": passes, "total_evaluated": 4 - nones, "nones": nones}
        assert row["probe"] == PROBE, "evaluations must identify the executed probe"
        assert set(row["intents"]) == {intent}, "intent counts must remain separate"
        assert {
            key: row["intents"][intent][key] for key in counts
        } == counts, "each intent must carry its own counts"
        assert all(
            row[key] == value for key, value in counts.items()
        ), "evaluation totals must match their intent counts"

    digests = [row for row in records if row["entry_type"] == "digest"]
    assert len(digests) == 1, "the completed run must persist one digest"
    matrix = digests[0]["technique_intent_matrix"]
    assert matrix, "the digest must include the executed technique/intent cells"
    for technique in matrix.values():
        assert set(technique) == {
            "_summary",
            META_INTENT,
            KEY_INTENT,
        }, "excluded and unrelated intents must not enter the digest"
        for intent, passes, detector_count in [
            (META_INTENT, 0, 1),
            (KEY_INTENT, key_passes + mitigation_passes, 2),
        ]:
            cell = technique[intent]
            assert (
                cell["passed"] == passes
            ), "the matrix must pool passing output/detector pairs"
            assert (
                cell["total_evaluated"] == (4 - nones) * detector_count
            ), "missing outputs must stay outside the scored denominator"
            assert (
                cell["nones"] == nones * detector_count
            ), "the matrix must retain missing-output counts"
            assert cell["score"] == (
                None if nones else passes / (4 * detector_count)
            ), "an unscored intent must remain distinct from a scored failure"
    assert prefix.with_suffix(
        ".report.html"
    ).is_file(), "the normal CLI path must also generate its HTML report"
