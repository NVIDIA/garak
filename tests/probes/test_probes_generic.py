import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

from garak import _plugins
from garak.probes.generic import CustomPrompts


class TestGenericProbe:
    """Tests for CustomPrompts class"""

    def test_custom_prompts_requires_primary_detector(self):
        """Test that CustomPrompts without primary_detector raises ValueError"""
        config = {
            "probes": {
                "generic": {
                    "CustomPrompts": {
                        "prompts": None  # Will use default
                        # Missing primary_detector - should error
                    }
                }
            }
        }
        
        with pytest.raises(ValueError, match="requires 'primary_detector'"):
            CustomPrompts(config_root=config)

    def test_custom_prompts_loads_from_txt_file(self):
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
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 3
            assert probe.prompts[0] == "prompt1"
            assert probe.prompts[1] == "prompt2"
            assert probe.prompts[2] == "prompt3"
            assert probe.primary_detector == "always.Pass"
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_loads_from_json_array(self):
        """Test that CustomPrompts can load prompts from JSON array"""
        data = ["json_prompt1", "json_prompt2"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts == data
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_loads_from_json_object_with_metadata(self):
        """Test that CustomPrompts can load prompts from JSON object with metadata"""
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
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "dan.DAN"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 3
            assert probe.prompts == data["prompts"]
            assert probe.goal == data["goal"]  # metadata callback should set
            assert probe.tags == data["tags"]
            assert probe.description == data["description"]
            assert probe.primary_detector == "dan.DAN"
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_metadata_callback_preserves_defaults(self):
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
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "goal": "default goal from config",
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert probe.goal == "default goal from config"  # From config, not JSON
            assert probe.tags == []  # Default
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_uses_default_prompts_when_none(self):
        """Test that CustomPrompts falls back to default prompts file when prompts=None"""
        config = {
            "probes": {
                "generic": {
                    "CustomPrompts": {
                        "prompts": None,  # Will use default
                        "primary_detector": "always.Pass"
                    }
                }
            }
        }
        
        # Should use default file from data/generic/custom_prompts_simple.json
        probe = CustomPrompts(config_root=config)
        assert len(probe.prompts) > 0  # Should have loaded default prompts
        assert probe.primary_detector == "always.Pass"

    def test_custom_prompts_loads_from_url(self):
        """Test that CustomPrompts can load prompts from HTTP URL"""
        mock_response = Mock()
        mock_response.json.return_value = ["url_prompt1", "url_prompt2"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": "https://example.com/prompts.json",
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts == ["url_prompt1", "url_prompt2"]

    def test_custom_prompts_has_primary_detector(self):
        """Test that CustomPrompts has primary_detector set"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "dan.DAN"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert probe.primary_detector == "dan.DAN"
            assert probe.extended_detectors == []
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_active_false(self):
        """Test that CustomPrompts is not active by default"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert probe.active is False
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_inherits_from_probe(self):
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
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = CustomPrompts(config_root=config)
            assert isinstance(probe, garak.probes.Probe)
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_loads_with_plugin_system(self):
        """Test that CustomPrompts can be loaded via _plugins.load_plugin"""
        data = ["plugin_prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            probe = _plugins.load_plugin("probes.generic.CustomPrompts", config_root=config)
            assert probe is not None
            assert isinstance(probe, CustomPrompts)
            assert len(probe.prompts) == 1
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_file_not_found_error(self):
        """Test that CustomPrompts raises FileNotFoundError for missing files"""
        config = {
            "probes": {
                "generic": {
                    "CustomPrompts": {
                        "prompts": "/nonexistent/path/prompts.txt",
                        "primary_detector": "always.Pass"
                    }
                }
            }
        }
        
        with pytest.raises(FileNotFoundError):
            CustomPrompts(config_root=config)

    def test_custom_prompts_unsupported_format_error(self):
        """Test that CustomPrompts raises ValueError for unsupported file formats"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("data,data,data")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            with pytest.raises(ValueError, match="Unsupported file format"):
                CustomPrompts(config_root=config)
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_empty_file_error(self):
        """Test that CustomPrompts raises ValueError for empty files"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("\n\n\n")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "generic": {
                        "CustomPrompts": {
                            "prompts": temp_path,
                            "primary_detector": "always.Pass"
                        }
                    }
                }
            }
            with pytest.raises(ValueError, match="No data found"):
                CustomPrompts(config_root=config)
        finally:
            Path(temp_path).unlink()
