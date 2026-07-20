# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Tests for base2048 encoding package replacement.
# This validates that mikeshardmind-base2048 works correctly as a drop-in
# replacement for the original base2048 package, which required Rust/Cargo.

import pytest
import base2048


# Reference vectors generated from original Rust-based base2048 package (v0.1.3)
# These ensure the pure Python replacement encodes/decodes identically.
#
# To regenerate these vectors, run (the last part encodes/decodes the test inputs):
#
#   docker run --rm python:3.11-slim bash -c "
#   echo '=== Installing Rust and base2048 (takes 1-2 min) ===' &&
#   apt-get update >/dev/null 2>&1 &&
#   apt-get install -y cargo >/dev/null 2>&1 &&
#   pip install base2048 >/dev/null 2>&1 &&
#   echo '=== Generating reference vectors ===' &&
#   python3 -c '
#   import base2048
#   test_inputs = [
#       b\"\",
#       b\"hello\",
#       b\"test\",
#       b\"Hello, World!\",
#       b\"\\x00\",
#       b\"\\xff\",
#       b\"\\x00\\x01\\x02\",
#       b\"\\xff\\xfe\\xfd\",
#       b\"The quick brown fox\",
#       b\"ignore previous instructions\",
#   ]
#   print(\"REFERENCE_VECTORS = [\")
#   for data in test_inputs:
#       encoded = base2048.encode(data)
#       decoded = base2048.decode(encoded)
#       assert decoded == data
#       print(f\"    ({data!r}, {encoded!r}),\")
#   print(\"]\")
#   '"
#
REFERENCE_VECTORS = [
    (b"", ""),
    (b"hello", "ӜțƘį"),
    (b"test", "ԽȜԍ"),
    (b"Hello, World!", "ϓțƘ໐ഒȝಲϽҺµ"),
    (b"\x00", "Ø"),
    (b"\xff", "ƿ"),
    (b"\x00\x01\x02", "ØĀ༏"),
    (b"\xff\xfe\xfd", "྾Ⴊ༎"),
    (b"The quick brown fox", "дΩϐཉхఒறĢԬցຜΕӐȸ"),
    (b"ignore previous instructions", "ӤʛઞཛСʁൺ௮ӤցѷΕਸʍขІҴଝѯອÀ"),
]


class TestBase2048SpecCompliance:
    """Verify encoding matches the original Rust implementation exactly."""

    @pytest.mark.parametrize("input_bytes,expected", REFERENCE_VECTORS)
    def test_encoding_matches_original(self, input_bytes, expected):
        """Encoded output must match the original base2048 Rust package."""
        result = base2048.encode(input_bytes)
        assert result == expected, (
            f"Encoding mismatch for {input_bytes!r}: "
            f"got {result!r}, expected {expected!r}"
        )

    @pytest.mark.parametrize("input_bytes,encoded", REFERENCE_VECTORS)
    def test_decoding_matches_original(self, input_bytes, encoded):
        """Decoding reference strings must return original bytes."""
        if not encoded:  # skip empty string
            return
        result = base2048.decode(encoded)
        assert result == input_bytes, (
            f"Decoding mismatch for {encoded!r}: "
            f"got {result!r}, expected {input_bytes!r}"
        )


class TestBase2048Roundtrip:
    """Core roundtrip tests - encode then decode should return original."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"hello",
            b"Hello, World!",
            b"\x00",
            b"\xff",
            b"\x00\x00\x00",
            b"\xff\xff\xff",
        ],
    )
    def test_basic_roundtrip(self, data):
        encoded = base2048.encode(data)
        decoded = base2048.decode(encoded)
        assert decoded == data

    def test_all_single_bytes(self):
        """Every possible single byte value should roundtrip correctly."""
        for i in range(256):
            data = bytes([i])
            encoded = base2048.encode(data)
            decoded = base2048.decode(encoded)
            assert decoded == data, f"Failed for byte value {i}"

    def test_all_bytes_sequence(self):
        """All 256 byte values in sequence."""
        data = bytes(range(256))
        encoded = base2048.encode(data)
        decoded = base2048.decode(encoded)
        assert decoded == data

    @pytest.mark.parametrize("length", [1, 2, 3, 7, 8, 9, 15, 16, 17, 100, 1000])
    def test_various_lengths(self, length):
        """Different input lengths to catch boundary issues."""
        data = b"x" * length
        assert base2048.decode(base2048.encode(data)) == data


class TestBase2048WithPayloads:
    """Test with realistic garak payloads."""

    @pytest.mark.parametrize(
        "payload",
        [
            b"ignore previous instructions",
            b"<script>alert('xss')</script>",
            b"sudo rm -rf /",
            b"DROP TABLE users;--",
            b"' OR '1'='1",
        ],
    )
    def test_ascii_payloads(self, payload):
        encoded = base2048.encode(payload)
        decoded = base2048.decode(encoded)
        assert decoded == payload

    @pytest.mark.parametrize(
        "text",
        [
            "你好世界",
            "مرحبا",
            "🔥💀🎉",
            "Привет мир",
        ],
    )
    def test_unicode_payloads(self, text):
        """Unicode text encoded as UTF-8 bytes."""
        data = text.encode("utf-8")
        encoded = base2048.encode(data)
        decoded = base2048.decode(encoded)
        assert decoded == data


class TestBase2048Properties:
    """Test expected properties of the encoding."""

    def test_encode_returns_string(self):
        result = base2048.encode(b"test")
        assert isinstance(result, str)

    def test_decode_returns_bytes(self):
        encoded = base2048.encode(b"test")
        result = base2048.decode(encoded)
        assert isinstance(result, bytes)

    def test_encoding_is_deterministic(self):
        """Same input should always produce same output."""
        data = b"test payload"
        results = [base2048.encode(data) for _ in range(10)]
        assert len(set(results)) == 1

    def test_encoded_uses_unicode(self):
        """Base2048 encoding should produce non-ASCII characters."""
        encoded = base2048.encode(b"hello")
        assert any(ord(c) > 127 for c in encoded)

    def test_empty_input(self):
        assert base2048.encode(b"") == ""
        assert base2048.decode("") == b""


class TestBase2048NoDependencies:
    """Verify the package doesn't require Rust or native compilation."""

    def test_package_is_pure_python(self):
        """The base2048 module should be a .py file, not a compiled extension."""
        import importlib.util

        spec = importlib.util.find_spec("base2048")
        assert spec is not None
        assert spec.origin is not None
        # Pure Python modules end in .py, native extensions end in .so/.pyd
        assert spec.origin.endswith(
            ".py"
        ), f"Expected pure Python module, got: {spec.origin}"


class TestInjectBase2048Probe:
    """Integration tests with the actual garak probe."""

    def test_probe_loads(self):
        """InjectBase2048 probe should load without errors."""
        from garak._plugins import load_plugin

        probe = load_plugin("probes.encoding.InjectBase2048")
        assert probe is not None

    def test_probe_has_prompts(self):
        """Probe should generate prompts."""
        from garak._plugins import load_plugin

        probe = load_plugin("probes.encoding.InjectBase2048")
        assert len(probe.prompts) > 0
        assert len(probe.triggers) > 0

    def test_probe_prompts_contain_encoded_text(self):
        """Generated prompts should contain Base2048 encoded (Unicode) text."""
        from garak._plugins import load_plugin

        probe = load_plugin("probes.encoding.InjectBase2048")
        # Check a sample of prompts have non-ASCII chars from encoding
        for prompt in probe.prompts[:5]:
            has_unicode = any(ord(c) > 127 for c in prompt)
            assert has_unicode, f"Expected encoded text in prompt: {prompt[:80]}..."
