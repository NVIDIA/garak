```python
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from typing import List, Optional

# Import the module under test. Adjust path as needed.
from garak import judge
from garak.attempt import Attempt


# ===== Fixtures =====

@pytest.fixture
def mock_config():
    """Return a config dict mock."""
    config = {
        "generators": {},
        "system_prompt_judge": "You are a judge.",
        "system_prompt_on_topic": "Is this on topic?",
        "custom_system_prompt": None,
    }
    return config


@pytest.fixture
def mock_attempt():
    """Return a mock Attempt object with necessary attributes."""
    attempt = MagicMock(spec=Attempt)
    attempt.outputs = ["output1"]
    attempt.notes = {"is_adversarial": True, "some_key": "value"}
    return attempt


# ===== Tests for JudgeBase =====

class TestJudgeBase:
    """Tests for the base Judge class (assuming it's named JudgeBase or Judge)."""

    def test_init_default_config(self):
        """Judge should use default config if no config_root provided."""
        j = judge.Judge()
        assert j.config_root is not None

    def test_init_custom_config(self, mock_config):
        """Judge should accept custom config_root."""
        j = judge.Judge(config_root=mock_config)
        assert j.config_root == mock_config

    def test_load_generator_default(self):
        """_load_generator should return expected structure."""
        j = judge.Judge()
        result = j._load_generator()
        assert result == {"generators": {}}

    def test_detect_empty_outputs(self):
        """detect should return empty list for empty outputs."""
        j = judge.Judge()
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = []
        result = j.detect(attempt)
        assert result == []

    def test_detect_all_none_outputs(self):
        """detect should return list of None when all outputs are None."""
        j = judge.Judge()
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = [None, None]
        result = j.detect(attempt)
        assert result == [None, None]

    def test_detect_with_None_and_str(self):
        """detect should return None for None output and a score for valid."""
        j = judge.Judge()
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = [None, "valid_output"]
        # judge base detect should treat None as None, others as float
        result = j.detect(attempt)
        assert result[0] is None
        assert isinstance(result[1], float)

    def test_detect_invalid_attempt_type(self):
        """detect should raise TypeError if attempt is not Attempt."""
        j = judge.Judge()
        with pytest.raises(TypeError):
            j.detect("not an attempt")

    def test_detect_missing_outputs_attr(self):
        """detect should raise AttributeError if attempt lacks outputs."""
        j = judge.Judge()
        attempt = MagicMock(spec=Attempt)
        del attempt.outputs
        with pytest.raises(AttributeError):
            j.detect(attempt)


# ===== Tests for OnTopicJudge =====

class TestOnTopicJudge:
    """Tests for OnTopicJudge subclass."""

    def test_init_has_system_prompt_on_topic(self, mock_config):
        """OnTopicJudge should store system prompt from config."""
        j = judge.OnTopicJudge(config_root=mock_config)
        assert hasattr(j, "system_prompt_on_topic")
        assert j.system_prompt_on_topic == mock_config["system_prompt_on_topic"]

    def test_detect_calls_on_topic_score(self, mock_attempt):
        """detect should call on_topic_score for each output."""
        j = judge.OnTopicJudge()
        j.on_topic_score = MagicMock(return_value=[0.5])
        result = j.detect(mock_attempt)
        j.on_topic_score.assert_called_once_with(["output1"])
        assert result == [0.5]

    def test_detect_none_output(self, mock_attempt):
        """If output is None, detect should return None without calling on_topic_score."""
        j = judge.OnTopicJudge()
        j.on_topic_score = MagicMock()
        mock_attempt.outputs = [None]
        result = j.detect(mock_attempt)
        j.on_topic_score.assert_not_called()
        assert result == [None]

    def test_detect_multiple_outputs(self):
        """detect should return list of scores for multiple outputs."""
        j = judge.OnTopicJudge()
        j.on_topic_score = MagicMock(return_value=[0.8, 0.2])
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["good", "bad"]
        result = j.detect(attempt)
        assert result == [0.8, 0.2]


# ===== Tests for PromptJudge =====

class TestPromptJudge:
    """Tests for a judge that uses system_prompt_judge (e.g., PromptJudge)."""

    def test_init_has_system_prompt_judge(self, mock_config):
        """PromptJudge should store system_prompt_judge from config."""
        j = judge.PromptJudge(config_root=mock_config)
        assert hasattr(j, "system_prompt_judge")
        assert j.system_prompt_judge == mock_config["system_prompt_judge"]

    def test_detect_uses_system_prompt_judge(self, mock_attempt):
        """detect should incorporate system prompt."""
        j = judge.PromptJudge()
        # mock the actual scoring method
        j._score_output = MagicMock(return_value=0.7)
        result = j.detect(mock_attempt)
        assert result == [0.7]

    def test_detect_with_custom_system_prompt(self, mock_config):
        """If custom_system_prompt is set, it should be used."""
        custom_prompt = "You are custom judge."
        mock_config["custom_system_prompt"] = custom_prompt
        j = judge.PromptJudge(config_root=mock_config)
        assert j.system_prompt_judge == custom_prompt


# ===== Tests for AdversarialJudge =====

class TestAdversarialJudge:
    """Tests for judge that checks is_adversarial note."""

    def test_detect_adversarial_true(self, mock_attempt):
        """When is_adversarial is True, detect should proceed normally."""
        j = judge.AdversarialJudge()
        # mock the actual evaluation
        j._evaluate = MagicMock(return_value=[0.9])
        result = j.detect(mock_attempt)
        j._evaluate.assert_called_once()
        assert result == [0.9]

    def test_detect_adversarial_false(self):
        """When is_adversarial is False, detect should return default safe score."""
        j = judge.AdversarialJudge()
        attempt = MagicMock(spec=Attempt)
        attempt.notes = {"is_adversarial": False}
        attempt.outputs = ["harmless"]
        result = j.detect(attempt)
        # Should return a list of safe scores (e.g., 0.0)
        assert result == [0.0]

    def test_detect_missing_is_adversarial_key(self):
        """If is_adversarial is missing from notes, default to True? (assumption)"""
        j = judge.AdversarialJudge()
        attempt = MagicMock(spec=Attempt)
        attempt.notes = {}
        attempt.outputs = ["something"]
        # Should treat as adversarial (default True)
        j._evaluate = MagicMock(return_value=[0.5])
        result = j.detect(attempt)
        j._evaluate.assert_called_once()
        assert result == [0.5]


# ===== Tests for CustomSystemPromptJudge =====

class TestCustomSystemPromptJudge:
    """Tests for judge that uses custom_system_prompt."""

    def test_uses_custom_prompt_when_set(self, mock_config):
        """If custom_system_prompt is set, it should override default."""
        mock_config["custom_system_prompt"] = "Custom prompt."
        j = judge.CustomSystemPromptJudge(config_root=mock_config)
        # Assuming it stores it as system_prompt
        assert j.system_prompt == "Custom prompt."

    def test_ignores_custom_prompt_when_none(self, mock_config):
        """If custom_system_prompt is None, default system prompt should be used."""
        j = judge.CustomSystemPromptJudge(config_root=mock_config)
        # Assuming it uses a default system prompt
        assert hasattr(j, "system_prompt")
        assert j.system_prompt != "Custom prompt."


# ===== Edge Cases and Error Handling =====

class TestEdgeCases:
    """General edge cases across judges."""

    @pytest.mark.parametrize("judge_cls", [
        judge.Judge,
        judge.OnTopicJudge,
        judge.PromptJudge,
        judge.AdversarialJudge,
    ])
    def test_detect_empty_outputs_list(self, judge_cls):
        """detect should return empty list for empty outputs."""
        j = judge_cls()
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = []
        result = j.detect(attempt)
        assert result == []

    @pytest.mark.parametrize("judge_cls", [
        judge.Judge,
        judge.OnTopicJudge,
        judge.PromptJudge,
        judge.AdversarialJudge,
    ])
    def test_detect_returns_list_of_float_or_none(self, judge_cls, mock_attempt):
        """detect should return a list of floats or Nones."""
        j = judge_cls()
        # For OnTopicJudge and PromptJudge we need to mock internal methods to return floats
        if hasattr(j, "on_topic_score"):
            j.on_topic_score = MagicMock(return_value=[0.5])
        if hasattr(j, "_evaluate"):
            j._evaluate = MagicMock(return_value=[0.5])
        if hasattr(j, "_score_output"):
            j._score_output = MagicMock(return_value=0.5)
        result = j.detect(mock_attempt)
        assert isinstance(result, list)
        for score in result:
            assert score is None or isinstance(score, float)

    def test_detect_none_attempt(self):
        """detect should handle None attempt gracefully (maybe raise)."""
        j = judge.Judge()
        with pytest.raises(AttributeError):  # accessing .outputs on None
            j.detect(None)

    def test_detect_outputs_wrong_type(self):
        """If outputs are not list, judge should handle."""
        j = judge.Judge()
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = "not a list"
        with pytest.raises(TypeError):
            j.detect(attempt)

    def test_config_root_none(self):
        """Judge should handle None config_root."""
        j = judge.Judge(config_root=None)
        # Should fallback to default config
        assert j.config_root is not None
```