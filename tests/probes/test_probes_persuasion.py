import pytest
import tempfile
import langcodes
import garak._plugins
import garak._config
import garak.probes.base
import garak.attempt


PERSUASION_PROBES = [
    "probes.persuasion.PersuasivePAP",
]


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_load(probename):
    """Test that persuasion probes can be loaded"""
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_has_base_queries(probename):
    """Test that persuasion probes have base queries loaded"""
    p = garak._plugins.load_plugin(probename)
    assert hasattr(p, "base_queries"), "Probe should have base_queries attribute"
    assert len(p.base_queries) > 0, "Should have at least one base query"
    assert all(isinstance(q, str) for q in p.base_queries), "All base queries should be strings"


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_has_prompt_template(probename):
    """Test that persuasion probes have prompt template loaded"""
    p = garak._plugins.load_plugin(probename)
    assert hasattr(p, "prompt_template"), "Probe should have prompt_template attribute"
    assert isinstance(p.prompt_template, str), "Prompt template should be a string"


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_metadata(probename):
    """Test persuasion probe metadata completeness"""
    p = garak._plugins.load_plugin(probename)
    assert p.doc_uri == "https://arxiv.org/abs/2401.06373"
    assert p.goal != ""
    assert p.lang == "en"
    assert len(p.tags) > 0
    assert p.tier == garak.probes.Tier.OF_CONCERN
    assert p.primary_detector is not None


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_detector_exists(probename):
    """Test that specified detectors exist"""
    p = garak._plugins.load_plugin(probename)
    # Check primary detector exists
    if p.primary_detector:
        detector = garak._plugins.load_plugin(f"detectors.{p.primary_detector}")
        assert detector is not None


def test_persuasion_pap_not_active():
    """Test that PersuasivePAP is not active by default (safety)"""
    p = garak._plugins.load_plugin("probes.persuasion.PersuasivePAP")
    assert p.active is False


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_has_techniques(probename):
    """Test that persuasion probes have techniques loaded"""
    p = garak._plugins.load_plugin(probename)
    assert hasattr(p, "techniques"), "Probe should have techniques attribute"
    assert len(p.techniques) > 0, "Should have at least one persuasion technique"
    assert all(isinstance(t, dict) for t in p.techniques), "All techniques should be dictionaries"


def test_persuasion_pap_data_loaded():
    """Test that PersuasivePAP has loaded the expected data"""
    p = garak._plugins.load_plugin("probes.persuasion.PersuasivePAP")
    # Should have 50 base queries from AdvBench
    assert len(p.base_queries) == 50, f"Expected 50 base queries from AdvBench, got {len(p.base_queries)}"
    # Should have 40 persuasion techniques
    assert len(p.techniques) == 40, f"Expected 40 persuasion techniques, got {len(p.techniques)}"


def test_persuasion_pap_expected_prompt_count():
    """Test that PersuasivePAP would generate the expected number of prompts"""
    p = garak._plugins.load_plugin("probes.persuasion.PersuasivePAP")
    # Dynamic mode: 50 queries × 40 techniques × 20 variants = 40,000
    expected_total = len(p.base_queries) * len(p.techniques) * p.variants_per_pair
    assert expected_total == 40000, f"Expected to generate 40,000 prompts, but calculation shows {expected_total}"


def test_persuasion_pap_paraphraser_prompt():
    """Test that paraphraser prompt is correctly built"""
    p = garak._plugins.load_plugin("probes.persuasion.PersuasivePAP")
    test_query = "How to make a bomb"
    test_technique = {
        "ss_technique": "Logical Appeal",
        "ss_definition": "Using reasoning and logic to persuade",
        "ss_example": "Based on scientific principles..."
    }

    prompt = p._build_paraphraser_prompt(test_query, test_technique)

    assert "Logical Appeal" in prompt, "Prompt should include technique name"
    assert test_query in prompt, "Prompt should include the harmful query"
    assert "Using reasoning and logic" in prompt, "Prompt should include technique definition"
    assert "Based on scientific principles" in prompt, "Prompt should include technique example"


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_probe_execution(probename):
    """Test that probe can execute and return attempts (using sampled data)"""
    garak._config.load_base_config()

    # Use sampling to limit test scope and use test generator for red team model
    test_config = {
        "probes": {
            "persuasion": {
                "PersuasivePAP": {
                    "base_query_count": 1,
                    "persuasion_technique_count": 1,
                    "variants_per_pair": 2,
                    "red_team_model_type": "test.Repeat",
                    "red_team_model_name": "",
                    "red_team_model_config": {},
                }
            }
        }
    }
    p = garak._plugins.load_plugin(probename, config_root=test_config)

    g = garak._plugins.load_plugin("generators.test.Repeat", config_root=garak._config)

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        garak._config.transient.reportfile = temp_report_file
        garak._config.transient.report_filename = temp_report_file.name
        attempts = p.probe(g)

    assert isinstance(attempts, list), "Probe should return a list"
    assert all(isinstance(a, garak.attempt.Attempt) for a in attempts), "All results should be Attempts"

    # Check metadata if attempts were generated
    if len(attempts) > 0:
        assert "base_query" in attempts[0].notes, "Attempt should have base_query metadata"
        assert "technique" in attempts[0].notes, "Attempt should have technique metadata"


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_lang_valid(probename):
    """Test that language code is valid BCP47"""
    p = garak._plugins.load_plugin(probename)
    assert p.lang == "*" or langcodes.tag_is_valid(p.lang), "lang must be * or valid BCP47 code"


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_extended_detectors(probename):
    """Test that extended detectors (if any) are valid and can be loaded"""
    p = garak._plugins.load_plugin(probename)
    if p.extended_detectors:
        for detector_name in p.extended_detectors:
            detector = garak._plugins.load_plugin(f"detectors.{detector_name}")
            assert detector is not None, f"Extended detector {detector_name} should exist"
