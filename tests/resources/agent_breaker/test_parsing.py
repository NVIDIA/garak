import json
import pytest
import garak.resources.agent_breaker.parsing as parsing


class TestExtractJsonObject:

    @pytest.mark.parametrize("payload", ["[]", "[1, 2]", "123", "null"])
    def test_non_object_payloads_raise_json_decode_error(self, payload):
        """Non-object JSON shapes must raise so callers degrade safely."""
        with pytest.raises(json.JSONDecodeError, match="No JSON object found"):
            parsing.extract_json_object(payload)

    def test_top_level_array_unwraps_first_object(self):
        """An object wrapped in a top-level array is extracted."""
        parsed = parsing.extract_json_object('[{"success": "YES"}]')
        assert parsed == {
            "success": "YES"
        }, "first object in a top-level array is returned"
