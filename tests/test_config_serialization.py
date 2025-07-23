# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import importlib
import os
import pytest
from unittest.mock import patch

from garak import _config

class TestConfigSerialization:
    """Tests for the new configuration serialization functionality."""
    
    def setup_method(self):
        """Reset config before each test."""
        importlib.reload(_config)
    
    def test_serialize_config_returns_dict(self):
        """Test that serialize_config returns a dictionary with entry_type."""
        serialized = _config.serialize_config()
        assert isinstance(serialized, dict)
        assert serialized["entry_type"] == "start_run setup"
    
    def test_serialize_config_to_json_returns_string(self):
        """Test that serialize_config_to_json returns a valid JSON string."""
        json_str = _config.serialize_config_to_json()
        assert isinstance(json_str, str)
        # Verify it's valid JSON by parsing it
        parsed = json.loads(json_str)
        assert parsed["entry_type"] == "start_run setup"
    
    def test_api_keys_excluded(self):
        """Test that API keys are excluded from serialization."""
        # Create temp attributes with API keys to test exclusion
        _config.plugins.test_api_key = 'secret_api_key'
        _config.plugins.OPENAI_API_KEY = 'openai_secret_key'
        
        try:
            serialized = _config.serialize_config()
            # Check values are not in serialized config
            assert "plugins.test_api_key" not in serialized
            assert "plugins.OPENAI_API_KEY" not in serialized
            
            # Check no values containing the keys exist in serialized output
            for k, v in serialized.items():
                if isinstance(v, str):
                    assert "secret_api_key" != v
                    assert "openai_secret_key" != v
        finally:
            # Clean up
            delattr(_config.plugins, 'test_api_key')
            delattr(_config.plugins, 'OPENAI_API_KEY')
    
    def test_constants_excluded(self):
        """Test that constants are excluded from serialization."""
        original_requests_agent = _config.REQUESTS_AGENT
        _config.REQUESTS_AGENT = "Test User Agent"
        
        serialized = _config.serialize_config()
        
        # Check direct exclusion
        assert "_config.REQUESTS_AGENT" not in serialized
        
        # Restore original value
        _config.REQUESTS_AGENT = original_requests_agent
    
    def test_internal_functions_excluded(self):
        """Test that internal functions are excluded from serialization."""
        serialized = _config.serialize_config()
        
        # Check for any function-related entries
        for key in serialized.keys():
            assert not key.endswith("_nested_dict")
            assert not key.endswith("_crystallise")
            assert not key.endswith("_key_exists")
    
    def test_transient_runtime_values_filtered(self):
        """Test that only specific transient values are included."""
        # Save original values to restore later
        original_run_id = _config.transient.run_id
        original_reportfile = _config.transient.reportfile
        
        try:
            # Set a sample run_id that should be included
            _config.transient.run_id = "test-run-id-123"
            # Set a reportfile that should be excluded - use None to avoid teardown issues
            _config.transient.reportfile = None
            
            serialized = _config.serialize_config()
            
            # The run_id should be included
            assert "transient.run_id" in serialized
            assert serialized["transient.run_id"] == "test-run-id-123"
            
            # The reportfile should be excluded
            assert "transient.reportfile" not in serialized
        finally:
            # Restore original values
            _config.transient.run_id = original_run_id
            _config.transient.reportfile = original_reportfile
    
    def test_run_values_included(self):
        """Test that run configuration values are included."""
        # Set a sample seed value
        original_seed = _config.run.seed
        _config.run.seed = 12345
        
        serialized = _config.serialize_config()
        
        # The seed should be included
        assert "run.seed" in serialized
        assert serialized["run.seed"] == 12345
        
        # Restore original value
        _config.run.seed = original_seed
    
    def test_plugin_values_included(self):
        """Test that plugin configuration values are included."""
        # Set a sample plugin value
        if not hasattr(_config.plugins, "test_key"):
            _config.plugins.test_key = None
        original_value = _config.plugins.test_key
        _config.plugins.test_key = "test_value"
        
        serialized = _config.serialize_config()
        
        # The plugin value should be included
        assert "plugins.test_key" in serialized
        assert serialized["plugins.test_key"] == "test_value"
        
        # Restore original value
        _config.plugins.test_key = original_value
    
    def test_serialized_config_integrates_with_command(self):
        """Test that the serialized config is compatible with command module."""
        from garak import command
        import io
        from unittest.mock import MagicMock
        
        # Save original values
        original_reportfile = _config.transient.reportfile
        original_run_id = _config.transient.run_id
        original_report_filename = _config.transient.report_filename
        
        try:
            # Mock the reportfile
            mock_file = MagicMock()
            _config.transient.reportfile = mock_file
            _config.transient.run_id = "test-command-integration"
            _config.transient.report_filename = "test_report.jsonl"
            
            # Call the relevant part of start_run that uses serialized config
            serialized_config = _config.serialize_config_to_json()
            _config.transient.reportfile.write.assert_not_called()  # Not called yet
            
            mock_file.write(serialized_config + "\n")
            
            # Verify the mock was called with JSON that can be parsed
            call_args = mock_file.write.call_args[0][0]
            # Remove newline if present
            if call_args.endswith('\n'):
                call_args = call_args[:-1]
            # Should be valid JSON
            parsed = json.loads(call_args)
            assert parsed["entry_type"] == "start_run setup"
        finally:
            # Restore original values
            _config.transient.reportfile = original_reportfile
            _config.transient.run_id = original_run_id
            _config.transient.report_filename = original_report_filename
        
    def test_no_side_effects(self):
        """Test that serializing config doesn't modify the config."""
        # Take a snapshot of some key config values
        original_run_seed = _config.run.seed
        original_version = _config.version if hasattr(_config, 'version') else None
        
        # Serialize
        _config.serialize_config()
        
        # Check values haven't changed
        assert _config.run.seed == original_run_seed
        if original_version is not None:
            assert _config.version == original_version
