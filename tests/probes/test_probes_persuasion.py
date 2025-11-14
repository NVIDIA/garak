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
def test_persuasion_has_prompts(probename):
    """Test that persuasion probes have prompts"""
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) > 0
    assert all(isinstance(prompt, str) for prompt in p.prompts)


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
def test_persuasion_prompts_non_empty(probename):
    """Test that all prompts are non-empty strings"""
    p = garak._plugins.load_plugin(probename)
    for prompt in p.prompts:
        assert len(prompt) > 0, "Prompts should not be empty strings"
        assert prompt.strip() == prompt or not prompt.endswith(" "), "Prompts should not have trailing spaces"


def test_persuasion_pap_prompt_count():
    """Test that PersuasivePAP has the expected number of prompts"""
    p = garak._plugins.load_plugin("probes.persuasion.PersuasivePAP")
    # Based on the implementation, there should be 6 prompts
    assert len(p.prompts) == 6, f"Expected 6 prompts, got {len(p.prompts)}"


@pytest.mark.parametrize("probename", PERSUASION_PROBES)
def test_persuasion_probe_execution(probename):
    """Test that probe can execute and return attempts"""
    garak._config.load_base_config()
    p = garak._plugins.load_plugin(probename, config_root=garak._config)
    g = garak._plugins.load_plugin("generators.test.Repeat", config_root=garak._config)

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        garak._config.transient.reportfile = temp_report_file
        garak._config.transient.report_filename = temp_report_file.name
        attempts = p.probe(g)

    assert isinstance(attempts, list), "Probe should return a list"
    assert len(attempts) > 0, "Probe should return at least one attempt"
    assert all(isinstance(a, garak.attempt.Attempt) for a in attempts), "All results should be Attempts"


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
