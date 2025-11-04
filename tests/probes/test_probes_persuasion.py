import pytest
import garak._plugins
import garak.probes.base


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
