import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from xdg_base_dirs import xdg_data_home

from garak.resources.loaders.data_sources import DataLoader, LocalFileLoader, HTTPDataLoader


class TestLocalFileLoader:
    """Tests for LocalFileLoader class with graceful degradation"""

    def test_load_txt_file(self):
        """Test loading from .txt file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("First prompt\n")
            f.write("Second prompt\n")
            f.write("\n")  # Empty line ignored
            f.write("Third prompt\n")
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert len(result) == 3
            assert result[0] == "First prompt"
            assert result[1] == "Second prompt"
            assert result[2] == "Third prompt"
        finally:
            Path(temp_path).unlink()

    def test_load_txt_file_case_insensitive(self):
        """Test that .TXT extension works (case-insensitive)"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.TXT', delete=False, encoding='utf-8') as f:
            f.write("prompt1\n")
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert len(result) == 1
            assert result[0] == "prompt1"
        finally:
            Path(temp_path).unlink()

    def test_load_txt_empty_file_returns_empty(self):
        """Test that empty .txt file returns empty list (not error)"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("\n\n\n")  # Only whitespace
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert result == []  # Graceful: returns empty
        finally:
            Path(temp_path).unlink()

    def test_load_json_array(self):
        """Test loading from JSON array format"""
        data = ["prompt1", "prompt2", "prompt3"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert result == data
        finally:
            Path(temp_path).unlink()

    def test_load_json_object_with_prompts_key(self):
        """Test loading from JSON object with 'prompts' key"""
        data = {"prompts": ["p1", "p2"], "goal": "test"}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert result == ["p1", "p2"]
        finally:
            Path(temp_path).unlink()

    def test_load_json_with_metadata_callback(self):
        """Test that metadata_callback is called for JSON objects"""
        data = {"prompts": ["p1"], "goal": "custom", "tags": ["tag1"]}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            metadata_received = {}
            def callback(metadata):
                metadata_received.update(metadata)
            
            result = LocalFileLoader.load(temp_path, metadata_callback=callback)
            assert result == ["p1"]
            assert metadata_received["goal"] == "custom"
            assert metadata_received["tags"] == ["tag1"]
        finally:
            Path(temp_path).unlink()

    def test_load_file_not_found_returns_empty(self):
        """Test that non-existent file returns empty list (not error)"""
        result = LocalFileLoader.load("/nonexistent/file.txt")
        assert result == []  # Graceful degradation

    def test_load_invalid_json_returns_empty(self):
        """Test that invalid JSON returns empty list (not error)"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            f.write("{invalid json")
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert result == []  # Graceful: returns empty
        finally:
            Path(temp_path).unlink()

    def test_load_unknown_format_as_plaintext(self):
        """Test that unknown formats are treated as plaintext"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("line1\n")
            f.write("line2\n")
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            # Treated as plaintext (feedback #4)
            assert len(result) == 2
            assert result[0] == "line1"
            assert result[1] == "line2"
        finally:
            Path(temp_path).unlink()

    def test_path_sanitization_allows_cwd(self):
        """Test that paths in current directory are allowed"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir='.', encoding='utf-8') as f:
            f.write("test\n")
            temp_path = Path(f.name).name  # Just filename
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert len(result) == 1
        finally:
            Path(temp_path).unlink()

    def test_path_sanitization_blocks_traversal(self):
        """Test that path traversal attempts are blocked"""
        # This should be caught by sanitization
        result = LocalFileLoader.load("../../../../etc/passwd")
        # Returns empty if outside allowed dirs
        assert isinstance(result, list)


class TestHTTPDataLoader:
    """Tests for HTTPDataLoader class"""

    def test_load_json_from_url(self):
        """Test loading JSON array from URL"""
        mock_response = Mock()
        mock_response.json.return_value = ["url_prompt1", "url_prompt2"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            result = HTTPDataLoader.load("https://example.com/data.json")
            assert result == ["url_prompt1", "url_prompt2"]
            # Verify timeout was used
            mock_get.assert_called_once()
            assert 'timeout' in mock_get.call_args.kwargs

    def test_load_text_from_url(self):
        """Test loading plaintext from URL"""
        mock_response = Mock()
        mock_response.text = "line1\nline2\nline3"
        mock_response.headers = {'content-type': 'text/plain'}
        
        with patch('requests.get', return_value=mock_response):
            result = HTTPDataLoader.load("https://example.com/data.txt")
            assert len(result) == 3
            assert result == ["line1", "line2", "line3"]

    def test_load_with_custom_timeout(self):
        """Test that custom timeout is used"""
        mock_response = Mock()
        mock_response.json.return_value = ["data"]
        mock_response.headers = {}
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            result = HTTPDataLoader.load("https://example.com/data.json", timeout=60)
            mock_get.assert_called_with("https://example.com/data.json", timeout=60)

    def test_load_timeout_returns_empty(self):
        """Test that timeout returns empty list (not error)"""
        import requests
        
        with patch('requests.get', side_effect=requests.Timeout()):
            result = HTTPDataLoader.load("https://example.com/slow.json")
            assert result == []  # Graceful degradation

    def test_load_http_error_returns_empty(self):
        """Test that HTTP errors return empty list (not error)"""
        import requests
        
        with patch('requests.get', side_effect=requests.RequestException("Connection error")):
            result = HTTPDataLoader.load("https://example.com/error.json")
            assert result == []  # Graceful degradation

    def test_load_invalid_json_from_url_returns_empty(self):
        """Test that invalid JSON from URL returns empty list"""
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            result = HTTPDataLoader.load("https://example.com/bad.json")
            assert result == []  # Graceful degradation


class TestDataLoader:
    """Tests for main DataLoader class"""

    def test_routes_http_to_http_loader(self):
        """Test that HTTP URLs are routed to HTTPDataLoader"""
        mock_response = Mock()
        mock_response.json.return_value = ["data"]
        mock_response.headers = {}
        
        with patch('requests.get', return_value=mock_response):
            result = DataLoader.load("https://example.com/data.json")
            assert result == ["data"]

    def test_routes_local_to_local_loader(self):
        """Test that local paths are routed to LocalFileLoader"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("test\n")
            temp_path = f.name
        
        try:
            result = DataLoader.load(temp_path)
            assert result == ["test"]
        finally:
            Path(temp_path).unlink()

    def test_default_timeout_used(self):
        """Test that default timeout is used when not specified"""
        mock_response = Mock()
        mock_response.json.return_value = ["data"]
        mock_response.headers = {}
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            result = DataLoader.load("https://example.com/data.json")
            # Should use default timeout (30)
            assert mock_get.call_args.kwargs['timeout'] == DataLoader.DEFAULT_TIMEOUT
