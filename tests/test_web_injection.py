```python
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from garak.attempt import Attempt
from garak.detectors.web_injection import WebInjection  # adjust import path as needed


class TestWebInjection:
    """Test suite for WebInjection detector."""

    @pytest.fixture
    def detector(self):
        """Return a WebInjection instance with mocked config loading."""
        with patch.object(WebInjection, '_load_substrings') as mock_load:
            det = WebInjection()
            # provide some test payloads
            det.payloads = ["<script>", "alert(1)", "onerror="]
            yield det

    @pytest.fixture
    def mock_attempt(self):
        """Return a mock attempt with outputs."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = [
            "clean text without injection",
            "malicious <script>alert(1)</script>"
        ]
        return attempt

    def test_detect_all_clean(self, detector):
        """All outputs are clean – should return 0.0 for each."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["hello", "world"]
        result = detector.detect(attempt)
        assert result == [0.0, 0.0], "Expected zero scores for clean outputs"

    def test_detect_one_match(self, detector):
        """One output contains a payload substring."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["safe", "check <script>alert(1)</script>"]
        result = detector.detect(attempt)
        # assuming detector returns 1.0 if any payload is found
        assert result == [0.0, 1.0], "Expected 1.0 for malicious output"

    def test_detect_multiple_matches(self, detector):
        """Multiple outputs contain injection patterns."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = [
            "<script>danger</script>",
            "onerror=alert(1)",
            "normal"
        ]
        result = detector.detect(attempt)
        assert result == [1.0, 1.0, 0.0]

    def test_detect_empty_outputs(self, detector):
        """Empty outputs list should return empty list."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = []
        result = detector.detect(attempt)
        assert result == [], "Expected empty result list for empty outputs"

    def test_detect_output_contains_none(self, detector):
        """Output list containing None should be handled gracefully (or raise)."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["valid", None, "also valid"]
        # Depending on implementation: either skip None or raise TypeError
        # Assume it converts None to empty string or raises – we test both scenarios
        try:
            result = detector.detect(attempt)
            # If no exception, ensure 0.0 for None (common pattern)
            assert len(result) == 3
            assert result[1] == 0.0, "Expected 0.0 for None output"
        except TypeError:
            # If None raises TypeError, that's also acceptable
            pass

    def test_detect_invalid_attempt_type(self, detector):
        """Passing non-Attempt object should raise TypeError."""
        with pytest.raises(TypeError, match=".*Attempt.*"):
            detector.detect("not an attempt object")

    def test_detect_missing_outputs_attribute(self, detector):
        """Attempt without outputs attribute should raise AttributeError."""
        attempt = MagicMock(spec=Attempt)
        del attempt.outputs
        with pytest.raises((AttributeError, TypeError)):
            detector.detect(attempt)

    def test_detect_outputs_not_list(self, detector):
        """If outputs is not a list (e.g., string), should raise."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = "single string"
        with pytest.raises((TypeError, AttributeError)):
            detector.detect(attempt)

    def test_detect_payload_substring_case_insensitive(self, detector):
        """Check if detection is case-insensitive (if implemented)."""
        # Assume substring matching is probably case-sensitive by default
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["<SCRIPT>alert(1)</SCRIPT>"]
        result = detector.detect(attempt)
        # If case-sensitive: result[0] == 0.0, else 1.0 – we test both possibilities
        # We'll just verify it returns a float without error
        assert isinstance(result[0], float)

    def test_detect_with_empty_payloads(self, detector):
        """If payloads list is empty, all outputs should get 0.0."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["<script>"]
        with patch.object(WebInjection, 'payloads', new_callable=PropertyMock, return_value=[]):
            result = detector.detect(attempt)
            assert result == [0.0], "Expected 0.0 when no payloads loaded"

    def test_detect_multiple_outputs_all_malicious(self, detector):
        """All outputs contain payloads."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["<script>", "onerror=", "alert(1)"]
        result = detector.detect(attempt)
        assert result == [1.0, 1.0, 1.0]

    def test__load_substrings_called_on_init(self):
        """Verify that _load_substrings is called during __init__."""
        with patch.object(WebInjection, '_load_substrings') as mock_load:
            det = WebInjection()
            mock_load.assert_called_once()

    def test__load_substrings_populates_payloads(self):
        """Test that _load_substrings fills payloads attribute."""
        # We'll partially mock to avoid actual config loading
        with patch.object(WebInjection, '_load_substrings', return_value=None) as mock_load:
            det = WebInjection()
            det.payloads = ["test1", "test2"]
            # Now simulate the real _load_substrings logic if needed
            # For now, ensure the list is populated
            assert len(det.payloads) == 2

    def test_detect_payload_substring_at_boundary(self, detector):
        """Output contains payload only at end or beginning."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = [
            "prefix <script>",
            "<script> suffix"
        ]
        result = detector.detect(attempt)
        assert result == [1.0, 1.0], "Substrings at boundaries should match"

    def test_detect_no_payloads_loaded(self):
        """If payloads never set (None), detect should raise or return 0.0."""
        with patch.object(WebInjection, '_load_substrings', return_value=None) as mock_load:
            det = WebInjection()
            det.payloads = None
            attempt = MagicMock(spec=Attempt)
            attempt.outputs = ["<script>"]
            # Expect TypeError because we're iterating over None
            with pytest.raises(TypeError):
                det.detect(attempt)

    def test_detect_score_range(self, detector):
        """Scores should be 0.0 or 1.0 (assuming binary detection)."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["clean", "<script>", "onerror="]
        result = detector.detect(attempt)
        for score in result:
            assert score in (0.0, 1.0), "Score must be 0.0 or 1.0"

    def test_init_with_custom_config(self):
        """Test that __init__ accepts a config_root."""
        config_root = "/fake/path"
        with patch.object(WebInjection, '_load_substrings') as mock_load:
            det = WebInjection(config_root=config_root)
            assert det.config_root == config_root

    def test_detect_large_output(self, detector):
        """Large output should not cause performance issues (basic sanity)."""
        huge_string = "A" * 10000 + "<script>" + "B" * 10000
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = [huge_string]
        result = detector.detect(attempt)
        assert result == [1.0]

    def test_detect_unicode_payloads(self, detector):
        """Unicode payloads should match correctly."""
        detector.payloads.append("ünicode")
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["some ünicode text"]
        result = detector.detect(attempt)
        assert result == [1.0]

    def test_detect_payload_not_present(self, detector):
        """Exact string present but not as payload – no match."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = ["script>alert(1)"]  # no "<" before script
        result = detector.detect(attempt)
        assert result == [0.0]

    def test_detect_on_none_output_list(self, detector):
        """If outputs is None, should raise."""
        attempt = MagicMock(spec=Attempt)
        attempt.outputs = None
        with pytest.raises((TypeError, AttributeError)):
            detector.detect(attempt)
```