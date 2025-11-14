import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from garak.data_sources import DataLoader, LocalFileLoader, HTTPDataLoader


class TestLocalFileLoader:
    """Tests for LocalFileLoader class"""

    def test_load_txt_file(self):
        """Test loading prompts from a .txt file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("First prompt\n")
            f.write("Second prompt\n")
            f.write("\n")  # Empty line should be ignored
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

    def test_load_txt_file_empty_lines_only(self):
        """Test that file with only empty lines raises ValueError"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("\n\n\n")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="No data found"):
                LocalFileLoader.load(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_json_array(self):
        """Test loading prompts from JSON array format"""
        data = ["prompt1", "prompt2", "prompt3"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert len(result) == 3
            assert result == data
        finally:
            Path(temp_path).unlink()

    def test_load_json_object_with_prompts_key(self):
        """Test loading prompts from JSON object with 'prompts' key"""
        data = {
            "prompts": ["prompt1", "prompt2"],
            "goal": "test goal",
            "description": "test description"
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert len(result) == 2
            assert result == ["prompt1", "prompt2"]
        finally:
            Path(temp_path).unlink()

    def test_load_json_object_with_metadata_callback(self):
        """Test that metadata callback is called with correct data"""
        data = {
            "prompts": ["prompt1"],
            "goal": "custom goal",
            "tags": ["tag1", "tag2"]
        }
        
        callback_called = False
        received_metadata = {}
        
        def test_callback(metadata):
            nonlocal callback_called, received_metadata
            callback_called = True
            received_metadata = metadata
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path, metadata_callback=test_callback)
            assert callback_called
            assert received_metadata["goal"] == data["goal"]
            assert received_metadata["tags"] == data["tags"]
            assert "prompts" not in received_metadata  # prompts should be excluded
        finally:
            Path(temp_path).unlink()

    def test_load_json_object_with_first_list_value(self):
        """Test loading from JSON object using first list-valued key when 'prompts' is absent"""
        data = {
            "questions": ["q1", "q2", "q3"],
            "metadata": "some value"
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert len(result) == 3
            assert result == ["q1", "q2", "q3"]
        finally:
            Path(temp_path).unlink()

    def test_load_json_object_no_list_values(self):
        """Test that JSON object with no list values raises ValueError"""
        data = {
            "key1": "value1",
            "key2": 123
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="No list found in JSON"):
                LocalFileLoader.load(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_json_invalid_format(self):
        """Test that invalid JSON raises ValueError"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            f.write("{invalid json")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                LocalFileLoader.load(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_json_empty_prompts(self):
        """Test that JSON with empty prompts list raises ValueError"""
        data = {"prompts": []}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="No data found"):
                LocalFileLoader.load(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_unsupported_format(self):
        """Test that unsupported file format raises ValueError"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("data")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Unsupported file format"):
                LocalFileLoader.load(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_nonexistent_file(self):
        """Test that nonexistent file raises FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            LocalFileLoader.load("/nonexistent/path/file.txt")

    def test_load_json_strips_whitespace(self):
        """Test that prompts are stripped of whitespace"""
        data = ["  prompt1  ", "  prompt2  "]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = LocalFileLoader.load(temp_path)
            assert result[0] == "prompt1"
            assert result[1] == "prompt2"
        finally:
            Path(temp_path).unlink()


class TestHTTPDataLoader:
    """Tests for HTTPDataLoader class"""

    def test_load_json_from_url(self):
        """Test loading JSON data from URL"""
        mock_response = Mock()
        mock_response.json.return_value = ["prompt1", "prompt2"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            result = HTTPDataLoader.load("https://example.com/data.json")
            assert len(result) == 2
            assert result == ["prompt1", "prompt2"]
            mock_get.assert_called_once_with("https://example.com/data.json", timeout=30)

    def test_load_json_object_from_url(self):
        """Test loading JSON object with prompts key from URL"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "prompts": ["prompt1", "prompt2"],
            "goal": "test goal"
        }
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            result = HTTPDataLoader.load("https://example.com/data.json")
            assert len(result) == 2
            assert result == ["prompt1", "prompt2"]

    def test_load_json_with_metadata_callback_from_url(self):
        """Test metadata callback is called when loading from URL"""
        callback_called = False
        received_metadata = {}
        
        def test_callback(metadata):
            nonlocal callback_called, received_metadata
            callback_called = True
            received_metadata = metadata
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "prompts": ["prompt1"],
            "goal": "url goal",
            "description": "url description"
        }
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            result = HTTPDataLoader.load(
                "https://example.com/data.json",
                metadata_callback=test_callback
            )
            assert callback_called
            assert received_metadata["goal"] == "url goal"
            assert received_metadata["description"] == "url description"

    def test_load_txt_from_url(self):
        """Test loading text data from URL"""
        mock_response = Mock()
        mock_response.text = "prompt1\nprompt2\n\nprompt3"
        mock_response.headers = {'content-type': 'text/plain'}
        
        with patch('requests.get', return_value=mock_response):
            result = HTTPDataLoader.load("https://example.com/data.txt")
            assert len(result) == 3
            assert result == ["prompt1", "prompt2", "prompt3"]

    def test_load_url_network_error(self):
        """Test that network errors are handled properly"""
        import requests
        
        with patch('requests.get', side_effect=requests.RequestException("Network error")):
            with pytest.raises(ValueError, match="Failed to download"):
                HTTPDataLoader.load("https://example.com/data.json")

    def test_load_url_http_error(self):
        """Test that HTTP errors are handled properly"""
        import requests
        
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404")
        
        with patch('requests.get', return_value=mock_response):
            with pytest.raises(ValueError, match="Failed to download"):
                HTTPDataLoader.load("https://example.com/data.json")

    def test_load_url_invalid_json(self):
        """Test that invalid JSON from URL raises ValueError"""
        import json
        
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("error", "doc", 0)
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            with pytest.raises(ValueError, match="Invalid JSON"):
                HTTPDataLoader.load("https://example.com/data.json")

    def test_load_url_no_data(self):
        """Test that empty data from URL raises ValueError"""
        mock_response = Mock()
        mock_response.text = "\n\n\n"
        mock_response.headers = {'content-type': 'text/plain'}
        
        with patch('requests.get', return_value=mock_response):
            with pytest.raises(ValueError, match="No data found"):
                HTTPDataLoader.load("https://example.com/data.txt")

    def test_load_url_json_invalid_structure(self):
        """Test that JSON without prompts key or list raises ValueError"""
        mock_response = Mock()
        mock_response.json.return_value = {"key": "value"}
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            with pytest.raises(ValueError, match="JSON must be array or object with 'prompts' key"):
                HTTPDataLoader.load("https://example.com/data.json")

    def test_load_url_detects_json_by_extension(self):
        """Test that JSON format is detected by .json extension"""
        mock_response = Mock()
        mock_response.json.return_value = ["prompt1"]
        mock_response.headers = {}  # No content-type header
        
        with patch('requests.get', return_value=mock_response):
            result = HTTPDataLoader.load("https://example.com/data.json")
            assert result == ["prompt1"]

    def test_load_url_requires_requests_library(self):
        """Test that missing requests library raises informative error"""
        with patch.dict('sys.modules', {'requests': None}):
            with pytest.raises(ValueError, match="requests library required"):
                HTTPDataLoader.load("https://example.com/data.json")


class TestDataLoader:
    """Tests for main DataLoader class"""

    def test_load_routes_to_local_file(self):
        """Test that DataLoader routes to LocalFileLoader for local paths"""
        data = ["prompt1", "prompt2"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            result = DataLoader.load(temp_path)
            assert result == data
        finally:
            Path(temp_path).unlink()

    def test_load_routes_to_http_loader(self):
        """Test that DataLoader routes to HTTPDataLoader for http:// URLs"""
        mock_response = Mock()
        mock_response.json.return_value = ["prompt1"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            result = DataLoader.load("http://example.com/data.json")
            assert result == ["prompt1"]

    def test_load_routes_to_https_loader(self):
        """Test that DataLoader routes to HTTPDataLoader for https:// URLs"""
        mock_response = Mock()
        mock_response.json.return_value = ["prompt1"]
        mock_response.headers = {'content-type': 'application/json'}
        
        with patch('requests.get', return_value=mock_response):
            result = DataLoader.load("https://example.com/data.json")
            assert result == ["prompt1"]

    def test_load_with_path_object(self):
        """Test that DataLoader works with Path objects"""
        data = ["prompt1"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = Path(f.name)
        
        try:
            result = DataLoader.load(temp_path)
            assert result == data
        finally:
            temp_path.unlink()

    def test_load_passes_kwargs_to_loader(self):
        """Test that DataLoader passes kwargs to underlying loaders"""
        callback_called = False
        
        def test_callback(metadata):
            nonlocal callback_called
            callback_called = True
        
        data = {
            "prompts": ["prompt1"],
            "goal": "test"
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            DataLoader.load(temp_path, metadata_callback=test_callback)
            assert callback_called
        finally:
            Path(temp_path).unlink()

