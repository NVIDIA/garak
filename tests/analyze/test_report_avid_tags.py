import json
import os

import garak.analyze.report_avid
import garak.services.intentservice
from garak.analyze.report_avid import convert_to_avid


def test_convert_to_avid_intent_probe_without_intentservice(tmp_path, monkeypatch):
    """IntentProbe subclasses can't be constructed outside a run, the converter must not construct probes"""
    monkeypatch.setattr(garak.services.intentservice, "is_loaded", False)
    report_file = tmp_path / "intent.report.jsonl"
    lines = [
        {
            "entry_type": "eval",
            "probe": "grandma.GrandmaIntent",
            "detector": "always.Pass",
            "passed": 5,
            "total_evaluated": 10,
        },
    ]
    with open(report_file, "w") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    avid_path = convert_to_avid(str(report_file))
    assert os.path.exists(avid_path), "AVID file should be written"
    with open(avid_path, "r", encoding="utf-8") as f:
        reports = [json.loads(line) for line in f if line.strip()]
    assert len(reports) == 1, "one AVID report per probe"


def test_convert_to_avid_uses_tags_from_report_plugin_cache(tmp_path, monkeypatch):
    """AVID export reads the tags recorded in the report, not the current class tags"""
    recorded = ["avid-effect:security:S0100", "recorded:only"]
    report_file = tmp_path / "cache.report.jsonl"
    lines = [
        {
            "entry_type": "plugin_cache",
            "plugin_cache": {
                "version": "0.0.0",
                "probes": {"probes.test.Test": {"tags": recorded}},
            },
        },
        {
            "entry_type": "eval",
            "probe": "test.Test",
            "detector": "always.Pass",
            "passed": 5,
            "total_evaluated": 10,
        },
    ]
    with open(report_file, "w") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")

    seen = []
    real = garak.analyze.report_avid.probe_tags

    def spy(plugin_cache, probe):
        seen.append(real(plugin_cache, probe))
        return seen[-1]

    monkeypatch.setattr(garak.analyze.report_avid, "probe_tags", spy)
    avid_path = convert_to_avid(str(report_file))
    assert os.path.exists(avid_path)
    assert seen == [recorded]
