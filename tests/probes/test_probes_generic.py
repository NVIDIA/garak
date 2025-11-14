import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

from garak import _plugins
from garak.probes.generic import CustomPrompts


class TestGenericProbe:
    """Tests for CustomPrompts class"""

    def test_generic_probe_instantiation_without_prompts_raises_error(self):
        """Test that CustomPrompts without prompts raises ValueError"""
        config = {
            "probes": {
                "generic": {
                    "prompts": None
                }
            }
        }
        
        with pytest.raises(ValueError, match="CustomPrompts requires prompts"):
            CustomPrompts(config_root=config)

    def test_generic_probe_loads_prompts_from_txt_file(self):
        """Test that CustomPrompts can load prompts from .txt file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("prompt1\n")
            f.write("prompt2\n")
            f.write("prompt3\n")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 3
            assert probe.prompts[0] == "prompt1"
            assert probe.prompts[1] == "prompt2"
            assert probe.prompts[2] == "prompt3"
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_loads_prompts_from_json_array(self):
        """Test that CustomPrompts can load prompts from JSON array"""
        data = ["json_prompt1", "json_prompt2"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts == data
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_loads_prompts_from_json_object(self):
        """Test that CustomPrompts can load prompts from JSON object with prompts key"""
        data = {
            "prompts": ["prompt_a", "prompt_b", "prompt_c"],
            "goal": "custom test goal",
            "description": "custom description",
            "tags": ["custom_tag1", "custom_tag2"]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 3
            assert probe.prompts == data["prompts"]
            assert probe.goal == data["goal"] # metadata callback should set the goal
            assert probe.tags == data["tags"] # metadata callback should set the tags
            assert probe.description == data["description"] # metadata callback should set the description
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_metadata_callback_preserves_defaults(self):
        """Test that metadata callback doesn't override when keys are missing"""
        data = {
            "prompts": ["prompt1"]
            # no goal, tags, or description
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path,
                        "goal": "default goal"
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert probe.goal == "default goal"
            assert probe.tags == []
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_loads_from_url(self):
        """Test that CustomPrompts can load prompts from HTTP URL"""
        mock_response = Mock()
        mock_response.json.return_value = ["url_prompt1", "url_prompt2"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            config = {
                "probes": {
                    "generic": {
                        "prompts": "https://example.com/prompts.json"
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts == ["url_prompt1", "url_prompt2"]

    def test_generic_probe_has_no_default_detector(self):
        """Test that CustomPrompts has no primary_detector by default"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert probe.primary_detector is None
            assert probe.extended_detectors == ["always.Fail"]
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_active_false(self):
        """Test that CustomPrompts is not active by default"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert probe.active is False
        finally:
            Path(temp_path).unlink()


    def test_generic_probe_inherits_from_probe(self):
        """Test that CustomPrompts is a proper Probe subclass"""
        import garak.probes
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert isinstance(probe, garak.probes.Probe)
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_loads_with_plugin_system(self):
        """Test that CustomPrompts can be loaded via _plugins.load_plugin"""
        data = ["plugin_prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            probe = _plugins.load_plugin("probes.generic.CustomPrompts", config_root=config)
            assert probe is not None
            assert isinstance(probe, CustomPrompts)
            assert len(probe.prompts) == 1
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_file_not_found_error(self):
        """Test that CustomPrompts raises FileNotFoundError for missing files"""
        config = {
            "probes": {
                "generic": {
                    "prompts": "/nonexistent/path/prompts.txt"
                }
            }
        }
        
        with pytest.raises(FileNotFoundError):
            CustomPrompts(config_root=config)

    def test_generic_probe_unsupported_format_error(self):
        """Test that CustomPrompts raises ValueError for unsupported file formats"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("data,data,data")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            with pytest.raises(ValueError, match="Unsupported file format"):
                CustomPrompts(config_root=config)
        finally:
            Path(temp_path).unlink()

    def test_generic_probe_empty_file_error(self):
        """Test that CustomPrompts raises ValueError for empty files"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("\n\n\n")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "prompts": temp_path
                    }
                }
            }
            with pytest.raises(ValueError, match="No data found"):
                CustomPrompts(config_root=config)
        finally:
            Path(temp_path).unlink()
