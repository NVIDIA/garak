# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import importlib
import pytest
from unittest.mock import patch

from garak import _config


class TestConfigDeserialization:
    """Tests for the configuration deserialization functionality."""
    
    def setup_method(self):
        """Reset config before each test."""
        importlib.reload(_config)
    
    def test_deserialize_config_returns_bool(self):
        """Test that deserialize_config returns a boolean status."""
        # Create a simple config dict
        config_dict = {"entry_type": "start_run setup", "_config.test_value": "test"}
        
        # Deserialize
        result = _config.deserialize_config(config_dict)
        
        # Check return value
        assert isinstance(result, bool)
        assert result is True
        
        # Check the value was set
        assert hasattr(_config, "test_value")
        assert _config.test_value == "test"
        
        # Clean up
        delattr(_config, "test_value")
    
    def test_deserialize_config_from_json(self):
        """Test that deserialize_config_from_json works with valid JSON."""
        # Create a simple JSON string
        json_str = '{"entry_type": "start_run setup", "_config.test_json": "json_value"}'
        
        # Deserialize
        result = _config.deserialize_config_from_json(json_str)
        
        # Check return value
        assert result is True
        
        # Check the value was set
        assert hasattr(_config, "test_json")
        assert _config.test_json == "json_value"
        
        # Clean up
        delattr(_config, "test_json")
    
    def test_deserialize_invalid_json(self):
        """Test that deserialize_config_from_json handles invalid JSON."""
        # Create an invalid JSON string
        json_str = '{"entry_type": "start_run setup", "invalid_json'
        
        # Deserialize should fail but not raise an exception
        result = _config.deserialize_config_from_json(json_str)
        
        # Check return value
        assert result is False
    
    def test_deserialize_invalid_config(self):
        """Test that deserialize_config handles invalid config input."""
        # Try with non-dict input
        result = _config.deserialize_config("not a dict")
        
        # Check return value
        assert result is False
    
    def test_deserialize_transient_values(self):
        """Test that transient values are properly deserialized."""
        # Create a config with transient values
        config_dict = {
            "entry_type": "start_run setup",
            "transient.run_id": "test-deserialized-run-id",
            "transient.config_dir": "/test/config/path"
        }
        
        # Save original values
        original_run_id = _config.transient.run_id
        original_config_dir = _config.transient.config_dir
        
        try:
            # Deserialize
            result = _config.deserialize_config(config_dict)
            
            # Check values were set
            assert _config.transient.run_id == "test-deserialized-run-id"
            assert _config.transient.config_dir == "/test/config/path"
        finally:
            # Restore original values
            _config.transient.run_id = original_run_id
            _config.transient.config_dir = original_config_dir
    
    def test_deserialize_plugin_values(self):
        """Test that plugin values are properly deserialized."""
        # Create a config with plugin values
        config_dict = {
            "entry_type": "start_run setup",
            "plugins.test_plugin_key": "test_plugin_value"
        }
        
        # Save original value if it exists
        has_original = hasattr(_config.plugins, "test_plugin_key")
        if has_original:
            original_value = _config.plugins.test_plugin_key
        
        try:
            # Deserialize
            result = _config.deserialize_config(config_dict)
            
            # Check value was set
            assert hasattr(_config.plugins, "test_plugin_key")
            assert _config.plugins.test_plugin_key == "test_plugin_value"
        finally:
            # Restore original value or clean up
            if has_original:
                _config.plugins.test_plugin_key = original_value
            else:
                delattr(_config.plugins, "test_plugin_key")
    
    def test_deserialize_plugin_specific_config(self):
        """Test that plugin-specific configuration is properly deserialized."""
        # Create a config with plugin-specific configuration
        config_dict = {
            "entry_type": "start_run setup",
            "plugins.specific": {
                "generators.test_generator": {"model": "test-model", "temperature": 0.7}
            }
        }
        
        # Ensure the plugin configuration structure exists
        if not hasattr(_config.plugins, "generators"):
            setattr(_config.plugins, "generators", {})
        
        if "test_generator" not in _config.plugins.generators:
            _config.plugins.generators["test_generator"] = {}
        
        # Save original value
        original_value = _config.plugins.generators["test_generator"]
        
        try:
            # Deserialize
            result = _config.deserialize_config(config_dict)
            
            # Check value was set - plugin config should be in plugins.generators["test_generator"]
            assert "test_generator" in _config.plugins.generators
            assert _config.plugins.generators["test_generator"]["model"] == "test-model"
            assert _config.plugins.generators["test_generator"]["temperature"] == 0.7
        finally:
            # Restore original value
            _config.plugins.generators["test_generator"] = original_value
    
    def test_deserialize_namespaced_attributes(self):
        """Test that namespaced attributes are properly deserialized."""
        # Create a config with namespaced attributes using only run namespace
        # First, ensure we have a test attribute we can modify
        if not hasattr(_config.run, "test_attribute"):
            _config.run.test_attribute = None
            
        # Save original values
        original_seed = _config.run.seed
        original_test_attribute = _config.run.test_attribute
        
        # Create config dict with multiple run attributes
        config_dict = {
            "entry_type": "start_run setup",
            "run.seed": 54321,
            "run.test_attribute": "test-value"
        }
        
        try:
            # Deserialize
            result = _config.deserialize_config(config_dict)
            
            # Check values were set
            assert _config.run.seed == 54321
            assert _config.run.test_attribute == "test-value"
        finally:
            # Restore original values
            _config.run.seed = original_seed
            _config.run.test_attribute = original_test_attribute
    
    def test_round_trip_serialization(self):
        """Test that serialization followed by deserialization preserves values."""
        # Set some test values
        original_seed = _config.run.seed
        _config.run.seed = 12345
        
        if not hasattr(_config.plugins, "test_round_trip"):
            _config.plugins.test_round_trip = None
        original_test_value = _config.plugins.test_round_trip
        _config.plugins.test_round_trip = "round_trip_value"
        
        try:
            # Serialize
            serialized = _config.serialize_config()
            
            # Change values
            _config.run.seed = 99999
            _config.plugins.test_round_trip = "changed_value"
            
            # Deserialize
            result = _config.deserialize_config(serialized)
            assert result is True
            
            # Check values were restored
            assert _config.run.seed == 12345
            assert _config.plugins.test_round_trip == "round_trip_value"
        finally:
            # Restore original values
            _config.run.seed = original_seed
            _config.plugins.test_round_trip = original_test_value
