import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

from garak import _plugins
from garak.probes.custom import Prompts


class TestCustomProbe:
    """Tests for custom.Prompts class"""

    def test_custom_prompts_loads_from_txt_file(self):
        """Test that custom.Prompts can load prompts from .txt file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("prompt1\n")
            f.write("prompt2\n")
            f.write("prompt3\n")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert len(probe.prompts) == 3
            assert probe.prompts[0] == "prompt1"
            assert probe.prompts[1] == "prompt2"
            assert probe.prompts[2] == "prompt3"
            assert probe.primary_detector == "always.Pass"  # Class-level default
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_loads_from_json_array(self):
        """Test that custom.Prompts can load prompts from JSON array"""
        data = ["json_prompt1", "json_prompt2"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts == data
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_loads_from_json_object_with_metadata(self):
        """Test that custom.Prompts can load prompts from JSON object with metadata"""
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
                    "custom": {
                        "Prompts": {
                            "source": temp_path,
                            "detector": "dan.DAN"
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
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
            # no goal, tags, or description in JSON
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path,
                            "goal": "default goal from config"
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert probe.goal == "default goal from config"  # From config, not JSON
            assert probe.tags == []  # Default
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_uses_default_prompts_when_empty(self):
        """Test that custom.Prompts falls back to default prompts file when source is empty"""
        config = {
            "probes": {
                "custom": {
                    "Prompts": {
                        "source": ""  # Empty string will use default
                    }
                }
            }
        }
        
        # Should use default file from data/custom/custom_prompts_simple.json
        probe = Prompts(config_root=config)
        assert len(probe.prompts) > 0  # Should have loaded default prompts
        assert probe.primary_detector == "always.Pass"

    def test_custom_prompts_loads_from_url(self):
        """Test that custom.Prompts can load prompts from HTTP URL"""
        mock_response = Mock()
        mock_response.json.return_value = ["url_prompt1", "url_prompt2"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": "https://example.com/prompts.json"
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts == ["url_prompt1", "url_prompt2"]

    def test_custom_prompts_has_primary_detector_at_class_level(self):
        """Test that custom.Prompts has primary_detector set at class level"""
        # Check class-level attribute
        assert Prompts.primary_detector == "always.Pass"
        
        # Verify it's used when instantiated
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert probe.primary_detector == "always.Pass"
            assert probe.extended_detectors == []
        finally:
            Path(temp_path).unlink()
    
    def test_custom_prompts_can_override_detector(self):
        """Test that detector can be overridden via config"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path,
                            "detector": "dan.DAN"
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert probe.primary_detector == "dan.DAN"  # Overridden via 'detector' param
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_active_false(self):
        """Test that custom.Prompts is not active by default"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert probe.active is False
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_inherits_from_probe(self):
        """Test that custom.Prompts is a proper Probe subclass"""
        import garak.probes
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            probe = Prompts(config_root=config)
            assert isinstance(probe, garak.probes.Probe)
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_loads_with_plugin_system(self):
        """Test that custom.Prompts can be loaded via _plugins.load_plugin"""
        data = ["plugin_prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            probe = _plugins.load_plugin("probes.custom.Prompts", config_root=config)
            assert probe is not None
            assert isinstance(probe, Prompts)
            assert len(probe.prompts) == 1
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_file_not_found(self):
        """Test that custom.Prompts raises ValueError when file not found"""
        config = {
            "probes": {
                "custom": {
                    "Prompts": {
                        "source": "/nonexistent/path/prompts.txt"
                    }
                }
            }
        }
        
        with pytest.raises(ValueError, match="Failed to load prompts"):
            Prompts(config_root=config)

    def test_custom_prompts_unknown_format_treated_as_plaintext(self):
        """Test that unknown formats are treated as plaintext"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("line1\n")
            f.write("line2\n")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            # Treated as plaintext
            probe = Prompts(config_root=config)
            assert len(probe.prompts) == 2
            assert probe.prompts[0] == "line1"
            assert probe.prompts[1] == "line2"
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_empty_file(self):
        """Test that custom.Prompts raises ValueError when file is empty"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("\n\n\n")  # Only whitespace
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            # Empty file should raise ValueError
            with pytest.raises(ValueError, match="Failed to load prompts"):
                Prompts(config_root=config)
        finally:
            Path(temp_path).unlink()

    def test_custom_prompts_invalid_json(self):
        """Test that custom.Prompts raises ValueError when JSON is invalid"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            f.write("{invalid json")
            temp_path = f.name
        
        try:
            config = {
                "probes": {
                    "custom": {
                        "Prompts": {
                            "source": temp_path
                        }
                    }
                }
            }
            # Invalid JSON should raise ValueError
            with pytest.raises(ValueError, match="Failed to load prompts"):
                Prompts(config_root=config)
        finally:
            Path(temp_path).unlink()
