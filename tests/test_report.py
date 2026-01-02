
import json
import os
import pytest
import pandas as pd

from garak.report import Report


# Helper functions

def validate_avid_report_structure(report):
    """Validate common AVID report structure"""
    assert "data_type" in report
    assert isinstance(report["data_type"], str)
    assert report["data_type"].lower() == "avid"
    
    assert "affects" in report
    assert "problemtype" in report
    assert "metrics" in report
    assert "impact" in report
    assert "references" in report


# Fixtures

@pytest.fixture
def sample_report():
    return "tests/_assets/report_test.report.jsonl"


@pytest.fixture
def sample_report_without_metadata(tmp_path):
    """Edge case: report file without metadata"""
    report_file = tmp_path / "test_no_metadata.report.jsonl"
    
    lines = [
        {
            "entry_type": "eval",
            "probe": "test.Test",
            "detector": "always.Pass",
            "passed": 5,
            "total": 10,
        },
    ]
    
    with open(report_file, "w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    
    return str(report_file)


@pytest.fixture
def exported_avid_report(sample_report, request):
    """Fixture that exports a report and returns AVID file path with auto-cleanup"""
    avid_file = sample_report.replace(".report", ".avid")
    
    # Register cleanup
    request.addfinalizer(lambda: os.path.exists(avid_file) and os.remove(avid_file))
    
    # Export the report
    Report(report_location=sample_report).load().get_evaluations().export()
    
    return avid_file


# Test __init__()

def test_init_creates_report_object():
    """Test Report object initialization"""
    r = Report(report_location="dummy_path")
    assert r.report_location == "dummy_path"
    assert r.records == []
    assert r.metadata is None
    assert r.evaluations is None
    assert r.scores is None


# Test .load()

def test_load_reads_report_file(sample_report):
    """Test loading a report file"""
    r = Report(report_location=sample_report).load()
    
    assert len(r.records) > 0


# Test .get_evaluations()


def test_get_evaluations_extracts_metadata(sample_report):
    """Test extracting metadata"""
    r = Report(report_location=sample_report).load().get_evaluations()
    
    # Check metadata was extracted
    assert r.metadata is not None # this ensures proper entry_type (currently 'start_run setup') for metadata
    assert "plugins.target_type" in r.metadata
    assert "plugins.target_name" in r.metadata
    assert r.metadata["plugins.target_type"]
    assert r.metadata["plugins.target_name"]

def test_get_evaluations_extracts_evaluations_and_scores(sample_report):
    """Test evaluations and scores were extracted"""
    r = Report(report_location=sample_report).load().get_evaluations()

    # Check evaluations were extracted
    assert isinstance(r.evaluations, pd.DataFrame)
    assert r.evaluations.empty is False

    columns = r.evaluations.columns.tolist()
    # key columns used in the report
    for col in ["probe", "probe_tags", "detector", "passed", "total", "score"]:
        assert col in columns
    
    # Check scores were calculated
    assert isinstance(r.scores, pd.DataFrame)
    assert r.scores.empty is False
    assert r.scores.index.name == "probe"
    assert r.scores.index.tolist() == r.evaluations["probe"].unique().tolist()


def test_get_evaluations_raises_error_when_no_evals(tmp_path):
    """Test get_evaluations raises ValueError when no evaluations exist"""
    report_file = tmp_path / "no_evals.report.jsonl"
    
    lines = [
        {"entry_type": "start_run setup", "plugins.target_type": "test"},
    ]
    
    with open(report_file, "w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    
    r = Report(report_location=str(report_file))
    r.load()
    
    with pytest.raises(ValueError, match="No evaluations to report"):
        r.get_evaluations()


# Test .export() resulting file

def test_export_creates_avid_report_file(exported_avid_report):
    """Test exporting creates an AVID report file"""
    # Check that output file was created
    assert os.path.exists(exported_avid_report)


def test_export_creates_avid_report_file_with_proper_structure(exported_avid_report):
    """Test exporting creates an AVID report file with proper structure"""
    with open(exported_avid_report, "r") as f:
        avid_reports = [json.loads(line) for line in f]

    assert len(avid_reports) > 0
    
    for report in avid_reports:
        # Validate basic AVID structure
        validate_avid_report_structure(report)
        
        # Additional checks
        assert "avid" in report["impact"]
        assert isinstance(report["references"], list)
        assert len(report["references"]) > 0
    

def test_export_includes_model_metadata_in_affects(exported_avid_report):
    """Test export includes model type and name in affects section"""
    with open(exported_avid_report, "r") as f:
        avid_reports = [json.loads(line) for line in f]
    
    for report in avid_reports:
        assert "affects" in report

        assert "deployer" in report["affects"]
        assert isinstance(report["affects"]["deployer"], list)
        assert len(report["affects"]["deployer"]) > 0
        
        assert "artifacts" in report["affects"]
        assert isinstance(report["affects"]["artifacts"], list)
        assert len(report["affects"]["artifacts"]) > 0

def test_export_includes_problemtype_in_report(exported_avid_report):
    """Test export includes problemtype in report"""
    with open(exported_avid_report, "r") as f:
        avid_reports = [json.loads(line) for line in f]
    
    for report in avid_reports:
        assert "problemtype" in report
        assert isinstance(report["problemtype"], dict)

        assert "classof" in report["problemtype"]
        assert report["problemtype"]["classof"] is not None

        assert "type" in report["problemtype"]
        assert report["problemtype"]["type"] is not None
        
        assert "description" in report["problemtype"]
        assert isinstance(report["problemtype"]["description"], dict)
        assert "value" in report["problemtype"]["description"]
        assert report["problemtype"]["description"]["value"] is not None
        assert "lang" in report["problemtype"]["description"]
        assert report["problemtype"]["description"]["lang"] is not None

def test_export_includes_metrics_in_report(exported_avid_report):
    """Test export includes metrics in report"""
    with open(exported_avid_report, "r") as f:
        avid_reports = [json.loads(line) for line in f]
    
    for report in avid_reports:
        assert "metrics" in report
        assert isinstance(report["metrics"], list)
        assert len(report["metrics"]) > 0

        metric = report["metrics"][0]
        assert metric.get("name") is not None
        assert metric.get("detection_method") is not None
        
        assert "results" in metric
        assert isinstance(metric["results"], dict)
        assert len(metric["results"]) > 0
        assert "index" in metric["results"]
        
        for key in ["detector", "passed", "total", "score"]:
            assert key in metric["results"]
            assert len(metric["results"][key]) == len(metric["results"]["index"])

def test_export_includes_vuln_id_in_avid_taxonomy(exported_avid_report):
    """Test export includes vuln_id field in AVID taxonomy (regression test)"""
    with open(exported_avid_report, "r") as f:
        avid_reports = [json.loads(line) for line in f]
    
    for report in avid_reports:
        assert "impact" in report
        assert "avid" in report["impact"]
        assert "vuln_id" in report["impact"]["avid"]

        assert "risk_domain" in report["impact"]["avid"]
        assert isinstance(report["impact"]["avid"]["risk_domain"], list)

        assert "sep_view" in report["impact"]["avid"]
        assert isinstance(report["impact"]["avid"]["sep_view"], list)

        assert "lifecycle_view" in report["impact"]["avid"]
        assert isinstance(report["impact"]["avid"]["lifecycle_view"], list)

        assert "taxonomy_version" in report["impact"]["avid"]

def test_export_works_without_metadata(sample_report_without_metadata):
    """Test export works when metadata is missing"""
    r = Report(report_location=sample_report_without_metadata).load().get_evaluations()
    
    # Should not crash even without metadata
    r.export()
    
    # Check that output file was created
    avid_file = sample_report_without_metadata.replace(".report", ".avid")
    assert os.path.exists(avid_file)
    
    os.remove(avid_file)

