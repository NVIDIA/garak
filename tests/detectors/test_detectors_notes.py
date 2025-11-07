from garak.attempt import Attempt, Message
import garak._plugins
import garak.detectors.notes
import pytest

@pytest.fixture
def detector():
    """Fixture to load the MatchSuccessBool detector"""
    return garak._plugins.load_plugin("detectors.notes.MatchSuccessBool")

def test_notes_match_success_bool_load(detector):
    """Test that the detector can be loaded"""
    assert isinstance(detector, garak.detectors.notes.MatchSuccessBool)

def test_notes_match_success_bool_output_success_true(detector):
    """Test that detector returns 1.0 when success is True in output notes"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    output.notes = {"success": True}
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [1.0]

def test_notes_match_success_bool_output_success_false(detector):
    """Test that detector returns 0.0 when success is False in output notes"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    output.notes = {"success": False}
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [0.0]

def test_notes_match_success_bool_multiple_outputs_mixed(detector):
    """Test detector with multiple outputs having different success values"""
    
    attempt = Attempt(prompt="test")
    
    output1 = Message("output 1")
    output1.notes = {"success": True}
    
    output2 = Message("output 2") 
    output2.notes = {"success": False}
    
    output3 = Message("output 3")
    output3.notes = {"success": True}
    
    attempt.outputs = [output1, output2, output3]
    
    results = detector.detect(attempt)
    assert results == [1.0, 0.0, 1.0]

def test_notes_match_success_bool_no_success_key(detector):
    """Test that detector returns 0.0 for outputs without success key"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    output.notes = {"other_field": "value"}
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [0.0]

def test_notes_match_success_bool_success_none(detector):
    """Test that detector returns 0.0 when success is None"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    output.notes = {"success": None}
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [0.0]

def test_notes_match_success_bool_empty_output_notes(detector):
    """Test that detector returns 0.0 for outputs with empty notes"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    output.notes = {}
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [0.0]

def test_notes_match_success_bool_no_output_notes(detector):
    """Test that detector returns 0.0 for outputs with no notes attribute"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [0.0]

def test_notes_match_success_bool_non_boolean_success(detector):
    """Test that detector returns 0.0 for outputs where success is not a boolean"""
    
    attempt = Attempt(prompt="test")
    
    non_boolean_values = ["yes", 1, "true", [1, 2, 3], {"key": "value"}, "false", 0]
    
    outputs = []
    for i, value in enumerate(non_boolean_values):
        output = Message(f"output {i}")
        output.notes = {"success": value}
        outputs.append(output)
    
    attempt.outputs = outputs
    
    results = detector.detect(attempt)
    expect_results = [0.0] * len(non_boolean_values)
    assert results == expect_results

def test_notes_match_success_bool_mixed_valid_invalid(detector):
    """Test detector with mix of valid and invalid success values"""
    
    attempt = Attempt(prompt="test")
    
    output1 = Message("output 1")
    output1.notes = {"success": True}
    
    output2 = Message("output 2")
    output2.notes = {"success": "yes"}
    
    output3 = Message("output 3")
    output3.notes = {"success": False}
    
    output4 = Message("output 4")
    output4.notes = {"other": "value"}
    
    output5 = Message("output 5")
    output5.notes = {"success": True}
    
    attempt.outputs = [output1, output2, output3, output4, output5]
    
    results = detector.detect(attempt)
    assert results == [1.0, 0.0, 0.0, 0.0, 1.0]

def test_notes_match_success_bool_notes_not_dict(detector):
    """Test that detector returns 0.0 for outputs where notes is not a dict"""
    
    attempt = Attempt(prompt="test")
    output = Message("some output")
    output.notes = "not a dict"
    attempt.outputs = [output]
    
    results = detector.detect(attempt)
    assert results == [0.0]
