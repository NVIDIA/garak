# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from garak import _config
import garak.analyze.report_digest
from garak.exception import ReportIncompatibleError


def _write_report_with_eval(tmp_path, eval_entry):
    report_path = tmp_path / "unknown_plugin.report.jsonl"
    with open(
        "tests/_assets/analyze/test.report.jsonl",
        encoding="utf-8",
    ) as f:
        setup_line = f.readline()
        init_line = f.readline()
    with open(report_path, "w", encoding="utf-8") as out:
        out.write(setup_line)
        out.write(init_line)
        out.write(json.dumps(eval_entry, ensure_ascii=False) + "\n")
    return str(report_path)


def test_build_digest_raises_on_unknown_probe(tmp_path) -> None:
    _config.load_base_config()
    _config.reporting.taxonomy = "owasp"
    eval_entry = {
        "entry_type": "eval",
        "probe": "does_not_exist.NoSuchProbe",
        "detector": "always.Pass",
        "passed": 1,
        "total_evaluated": 1,
        "fails": 0,
        "nones": 0,
        "total_processed": 1,
    }
    report_path = _write_report_with_eval(tmp_path, eval_entry)

    with pytest.raises(ReportIncompatibleError) as exc_info:
        garak.analyze.report_digest.build_digest(report_path)
    assert "does_not_exist.NoSuchProbe" in str(exc_info.value)


def test_build_digest_raises_on_unknown_detector(tmp_path) -> None:
    _config.load_base_config()
    _config.reporting.taxonomy = None
    eval_entry = {
        "entry_type": "eval",
        "probe": "test.Test",
        "detector": "does_not_exist.NoSuchDetector",
        "passed": 1,
        "total_evaluated": 1,
        "fails": 0,
        "nones": 0,
        "total_processed": 1,
    }
    report_path = _write_report_with_eval(tmp_path, eval_entry)

    with pytest.raises(ReportIncompatibleError) as exc_info:
        garak.analyze.report_digest.build_digest(report_path)
    assert "does_not_exist.NoSuchDetector" in str(exc_info.value)


def _pc(probe_tags, detectors=("d.D",)):
    """Minimal report_plugin_cache: probes carry tags; detectors carry a description."""
    return {
        "probes": {f"probes.{k}": {"tags": v} for k, v in probe_tags.items()},
        "detectors": {f"detectors.{d}": {"description": "x"} for d in detectors},
    }


def _tim(evals, pc):
    return garak.analyze.report_digest._compute_technique_intent_matrix(evals, pc)


def test_tim_single_cell():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {"S003": {"passed": 3, "total_evaluated": 6, "nones": 0}},
        }
    ]
    cell = _tim(evals, _pc({"grandma.Win10": ["demon:T:Tech"]}))["demon:T:Tech"]["S003"]
    assert cell == {
        "name": garak.analyze.report_digest.intent_names.get("S003"),
        "score": 0.5,
        "passed": 3,
        "total_evaluated": 6,
        "n_detectors": 1,
        "nones": 0,
    }, cell


def test_tim_pools_across_detectors():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.A",
            "intents": {"S003": {"passed": 0, "total_evaluated": 6, "nones": 0}},
        },
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.B",
            "intents": {"S003": {"passed": 3, "total_evaluated": 6, "nones": 0}},
        },
    ]
    pc = _pc({"grandma.Win10": ["demon:T:Tech"]}, detectors=("d.A", "d.B"))
    cell = _tim(evals, pc)["demon:T:Tech"]["S003"]
    assert cell["passed"] == 3 and cell["total_evaluated"] == 12, cell
    assert cell["n_detectors"] == 2, cell
    assert cell["score"] == pytest.approx(3 / 12), cell


def test_tim_pools_across_probes():
    evals = [
        {
            "entry_type": "eval",
            "probe": "malwaregen.Evasion",
            "detector": "m.AnyCode",
            "intents": {"S008code": {"passed": 37, "total_evaluated": 48, "nones": 0}},
        },
        {
            "entry_type": "eval",
            "probe": "malwaregen.SubFunctions",
            "detector": "m.AnyCode",
            "intents": {"S008code": {"passed": 29, "total_evaluated": 56, "nones": 0}},
        },
    ]
    pc = _pc(
        {
            "malwaregen.Evasion": ["demon:T:Tech"],
            "malwaregen.SubFunctions": ["demon:T:Tech"],
        },
        detectors=("m.AnyCode",),
    )
    cell = _tim(evals, pc)["demon:T:Tech"]["S008code"]
    assert cell["passed"] == 66 and cell["total_evaluated"] == 104, cell
    assert cell["n_detectors"] == 1, cell


def test_tim_attempts_deduped_across_detectors():
    pass


def test_tim_attempts_summed_across_probes():
    pass


def test_tim_multi_tag_replicates():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2, "nones": 0}},
        }
    ]
    m = _tim(evals, _pc({"grandma.Win10": ["demon:T:One", "demon:T:Two"]}))
    assert m["demon:T:One"]["S003"] == m["demon:T:Two"]["S003"], m


def test_tim_skips_eval_without_intents():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "passed": 1,
            "total_evaluated": 2,
        }
    ]
    m = _tim(evals, _pc({"grandma.Win10": ["demon:T:Tech"]}))
    assert m == {}, f"eval without intents should yield empty matrix, got {m}"


def test_tim_skips_probe_without_demon_tags():
    evals = [
        {
            "entry_type": "eval",
            "probe": "x.Y",
            "detector": "d.D",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2, "nones": 0}},
        }
    ]
    m = _tim(evals, _pc({"x.Y": ["owasp:llm01"]}))
    assert m == {}, f"probe without demon:* tags should contribute nothing, got {m}"


def test_tim_summary_counts():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.A",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2, "nones": 0}},
        },
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.B",
            "intents": {"S005": {"passed": 1, "total_evaluated": 2, "nones": 0}},
        },
    ]
    pc = _pc({"grandma.Win10": ["demon:T:Tech"]}, detectors=("d.A", "d.B"))
    summary = _tim(evals, pc)["demon:T:Tech"]["_summary"]
    assert summary == {
        "name": None,  # synthetic tag absent from tags.misp.tsv
        "description": None,
        "n_intents": 2,
        "n_detectors": 2,
    }, summary
    assert "score" not in summary


def test_tim_empty_when_no_intent_evals():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "passed": 1,
            "total_evaluated": 2,
        }
    ]
    m = _tim(evals, _pc({"grandma.Win10": ["demon:T:Tech"]}))
    assert m == {}, f"no intent-bearing evals should yield empty matrix, got {m}"


def test_tim_unknown_probe_raises():
    evals = [
        {
            "entry_type": "eval",
            "probe": "ghost.Probe",
            "detector": "d.D",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2, "nones": 0}},
        }
    ]
    with pytest.raises(ReportIncompatibleError):
        _tim(evals, _pc({"grandma.Win10": ["demon:T:Tech"]}))


def test_tim_keys_sorted():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {
                "S005": {"passed": 1, "total_evaluated": 2, "nones": 0},
                "S003": {"passed": 1, "total_evaluated": 2, "nones": 0},
            },
        }
    ]
    m = _tim(evals, _pc({"grandma.Win10": ["demon:T:B", "demon:T:A"]}))
    assert list(m) == sorted(m), list(m)
    for tech in m:
        intent_keys = [k for k in m[tech] if k != "_summary"]
        assert intent_keys == sorted(intent_keys), intent_keys


def test_tim_zero_total_score_none():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {"S003": {"passed": 0, "total_evaluated": 0, "nones": 0}},
        }
    ]
    cell = _tim(evals, _pc({"grandma.Win10": ["demon:T:Tech"]}))["demon:T:Tech"]["S003"]
    assert cell["score"] is None, cell
    assert cell["passed"] == 0 and cell["total_evaluated"] == 0, cell


def test_tim_cell_includes_nones():
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.A",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2, "nones": 3}},
        },
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.B",
            "intents": {"S003": {"passed": 2, "total_evaluated": 4, "nones": 1}},
        },
    ]
    pc = _pc({"grandma.Win10": ["demon:T:Tech"]}, detectors=("d.A", "d.B"))
    cell = _tim(evals, pc)["demon:T:Tech"]["S003"]
    assert cell["nones"] == 4, cell  # pooled across detectors
    assert cell["passed"] == 3 and cell["total_evaluated"] == 6, cell
    assert cell["score"] == pytest.approx(3 / 6), cell


def test_tim_missing_nones_raises():
    # nones is part of the eval.intents contract; absence is an incompatible report
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2}},
        }
    ]
    with pytest.raises(ReportIncompatibleError):
        _tim(evals, _pc({"grandma.Win10": ["demon:T:Tech"]}))


def test_tim_enrichment_populated_from_data_tables():
    technique = "demon:Language:Stylizing:Formal_language"
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {"S003": {"passed": 1, "total_evaluated": 2, "nones": 0}},
        }
    ]
    tech = _tim(evals, _pc({"grandma.Win10": [technique]}))[technique]
    expected_name, expected_descr = garak.analyze.report_digest.tag_descriptions[
        technique
    ]
    assert tech["_summary"]["name"] == expected_name, "technique name from misp table"
    assert (
        tech["_summary"]["description"] == expected_descr
    ), "technique description from misp table"
    assert tech["_summary"]["name"], "real technique resolves a non-empty name"
    assert (
        tech["S003"]["name"] == garak.analyze.report_digest.intent_names["S003"]
    ), "intent name from typology"
    assert tech["S003"]["name"], "real intent code resolves a non-empty name"


def test_tim_enrichment_none_fallback_for_unknown_codes():
    technique = "demon:does_not_exist"  # absent from tags.misp.tsv
    intent = "Z999"  # absent from trait_typology.json
    evals = [
        {
            "entry_type": "eval",
            "probe": "grandma.Win10",
            "detector": "d.D",
            "intents": {intent: {"passed": 1, "total_evaluated": 2, "nones": 0}},
        }
    ]
    tech = _tim(evals, _pc({"grandma.Win10": [technique]}))[technique]
    assert tech["_summary"]["name"] is None, "unknown technique tag -> name None"
    assert (
        tech["_summary"]["description"] is None
    ), "unknown technique tag -> description None"
    assert tech[intent]["name"] is None, "unknown intent code -> name None"


def test_runspec_renders_include_and_exclude_object():
    setup = {
        "run.spec": {
            "include": ["probes.dan", {"probes": "encoding"}],
            "exclude": ["probes.foo"],
        }
    }
    assert (
        garak.analyze.report_digest._runspec_to_probespec(setup)
        == "probes.dan, probes:encoding, -probes.foo"
    )


def test_runspec_string_passthrough():
    assert (
        garak.analyze.report_digest._runspec_to_probespec({"run.spec": "probes.dan"})
        == "probes.dan"
    )


def test_runspec_falls_back_when_absent():
    assert garak.analyze.report_digest._runspec_to_probespec({}) == "probes.*"
    assert (
        garak.analyze.report_digest._runspec_to_probespec(
            {"plugins.probe_spec": "probes.dan"}
        )
        == "probes.dan"
    ), "reports predating run.spec fall back to the legacy probe_spec"
