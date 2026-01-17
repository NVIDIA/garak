"""Data loaders used for loading external data:
(Currently supported)
- Local files (.txt, .json)
- HTTP(S) URLs

(Future)
- HF Datasets
- MLFlow data
.... and more
"""

import json
import logging
import requests
from urllib.parse import urlparse
from pathlib import Path
from typing import List, Optional, Union
from xdg_base_dirs import xdg_data_home, xdg_cache_home, xdg_config_home


class DataLoader:
    """Data loader supporting multiple source types.
    
    Examples:
        # Local file
        data = DataLoader.load("/path/to/file.json")
        
        # HTTP URL with timeout
        data = DataLoader.load("https://example.com/file.json", timeout=60)
        
        # Returns empty list on errors (logs warning)
        data = DataLoader.load("/bad/path.json")  # Returns []
    """
    
    DEFAULT_TIMEOUT = 30
    
    @staticmethod
    def load(source: Union[str, Path], timeout: Optional[int] = None, **kwargs) -> List[str]:
        """Main method to load data from external sources.
        
        Args:
            source: Path/URI to data source
                - Local: "file.txt", "file.json"
                - HTTP(S): "https://example.com/file.txt"
            timeout: Timeout for HTTP requests (default: 30s)
            **kwargs: Additional parameters (e.g., metadata_callback)
            
        Returns:
            List of strings, or empty list if loading fails
            
        Note:
            Errors are logged but don't crash - returns empty list.
        """
        source_str = str(source)
        timeout = timeout or DataLoader.DEFAULT_TIMEOUT
        
        # Route to appropriate loader based on URI scheme
        if urlparse(source_str).scheme.lower() in ['http', 'https']:
            return HTTPDataLoader.load(source_str, timeout=timeout, **kwargs)
        else:
            return LocalFileLoader.load(source_str, **kwargs)


class LocalFileLoader:
    """Loader for local files."""
    
    @staticmethod
    def _sanitize_path(file_path: Path) -> Path:
        """Sanitize file path to prevent traversal attacks.
        
        Ensures path is within allowed directories.
        Allows XDG dirs, current directory, and system temp directory.
        
        Args:
            file_path: Path to validate
            
        Returns:
            Resolved absolute path if within allowed directories, otherwise None
        """
        import tempfile
        
        # absolute path
        resolved = file_path.resolve()
        
        # Allowed base directories
        allowed_bases = [
            Path.cwd(),
            xdg_data_home(),
            xdg_cache_home(),
            xdg_config_home(),
            Path(tempfile.gettempdir()),
        ]
        
        # check if path is within any allowed base
        for base in allowed_bases:
            try:
                base = base.resolve()  # Resolve base too
                resolved.relative_to(base)
                return resolved  # within allowed directory
            except ValueError:
                continue  # not within this base, try next
        msg = (
            f"Path {file_path} is outside allowed directories. "
            f"Must be within: CWD, XDG dirs, or system temp."
        )

        # not within any allowed directory
        logging.error(msg)
        return None
    
    @staticmethod
    def load(file_path: Union[str, Path], **kwargs) -> List[str]:
        """Load data from local file.
        
        Supports: .txt, .json (case-insensitive), others treated as plaintext
        
        Args:
            file_path: Path to file
            **kwargs: metadata_callback for JSON metadata
            
        Returns:
            List of strings, or empty list if loading fails (logs warning)
        """
        try:
            file_path = Path(file_path)
            
            # Sanitize path
            file_path = LocalFileLoader._sanitize_path(file_path)
            
            if file_path is None or not file_path.exists():
                logging.warning("File not found in allowed directories: %s", file_path)
                return []
            
            # Case-insensitive extension check
            suffix = file_path.suffix.lower()
            
            if suffix == '.json':
                return LocalFileLoader._load_json(file_path, **kwargs)
            else:
                # Treat .txt and all unknown formats as plaintext
                return LocalFileLoader._load_txt(file_path)
                
        except Exception as e:
            logging.warning(
                "Failed to load data from %s: %s (returning empty list)",
                file_path, e
            )
            return []
    
    @staticmethod
    def _load_txt(file_path: Path) -> List[str]:
        """Load from text file (one item per line).
        
        Args:
            file_path: Path to .txt file
            
        Returns:
            List of non-empty lines, or empty list on error
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                items = [line.strip() for line in f if line.strip()]
            
            if not items:
                logging.warning("No data found in %s (file is empty)", file_path)
                return []
            
            logging.info("Loaded %d items from %s", len(items), file_path)
            return items
            
        except Exception as e:
            logging.warning(
                "Error reading text file %s: %s (returning empty list)",
                file_path, e
            )
            return []
    
    @staticmethod
    def _load_json(file_path: Path, **kwargs) -> List[str]:
        """Load from JSON file.
        
        Supports:
        - Array: ["item1", "item2"]
        - Object: {"prompts": ["item1", "item2"], "goal": "...", ...}
        
        If metadata_callback is provided, calls it with metadata dict.
        
        Args:
            file_path: Path to .json file
            **kwargs: metadata_callback (optional callable)
            
        Returns:
            List of strings, or empty list on error
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.warning(
                        "Invalid JSON in %s: %s (returning empty list)",
                        file_path, e
                    )
                    return []
            
            # Use shared JSON parser
            return _JSONParser.parse(data, str(file_path), **kwargs)
            
        except Exception as e:
            logging.warning(
                "Error loading JSON from %s: %s (returning empty list)",
                file_path, e
            )
            return []


class HTTPDataLoader:
    """Loader for HTTP(S) URLs."""
    
    @staticmethod
    def load(url: str, timeout: int = None, **kwargs) -> List[str]:
        """Load data from HTTP(S) URL.
        
        Args:
            url: HTTP(S) URL to data file
            timeout: Request timeout in seconds (default: 30)
            **kwargs: metadata_callback for JSON metadata
            
        Returns:
            List of strings, or empty list if download/parse fails
        """
        timeout = timeout or DataLoader.DEFAULT_TIMEOUT
        
        logging.info("Downloading from URL: %s (timeout=%ds)", url, timeout)
        
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
        
        except requests.HTTPError as e:
            logging.warning(
                "HTTP error downloading from %s: %s (returning empty list)",
                url, e
            )
            return []
            
        except requests.Timeout:
            logging.warning(
                "Timeout downloading from %s after %ds (returning empty list)",
                url, timeout
            )
            return []
            
        except requests.RequestException as e:
            logging.warning(
                "Failed to download from %s: %s (returning empty list)",
                url, e
            )
            return []
        
        try:
            # Detect format (case-insensitive)
            content_type = response.headers.get('content-type', '').lower()
            url_lower = url.lower()
            is_json = url_lower.endswith('.json') or 'application/json' in content_type
            if is_json:
                data = response.json()
                # Use shared JSON parser
                return _JSONParser.parse(data, url, **kwargs)
            else:
                # Parse as plaintext
                return HTTPDataLoader._parse_text(response, url)
        
        except json.JSONDecodeError as e:
            logging.warning(
                "Invalid JSON from %s: %s (returning empty list)",
                url, e
            )
            return []
                
        except Exception as e:
            logging.warning(
                "Error parsing data from %s: %s (returning empty list)",
                url, e
            )
            return []
    
    @staticmethod
    def _parse_text(response: requests.Response, url: str) -> List[str]:
        """Parse plaintext response.
        
        Args:
            response: requests Response object  
            url: Source URL (for logging)
            
        Returns:
            List of non-empty lines, or empty list on error
        """
        try:
            items = [
                line.strip() 
                for line in response.text.splitlines() 
                if line.strip()
            ]
            
            if not items:
                logging.warning("No data found in %s (file is empty)", url)
                return []
            
            logging.info("Loaded %d items from %s", len(items), url)
            return items
            
        except Exception as e:
            logging.warning(
                "Error parsing text from %s: %s (returning empty list)",
                url, e
            )
            return []

class _JSONParser:
    """Shared JSON parsing logic for both local and HTTP sources."""
    
    @staticmethod
    def parse(data, source_name: str, **kwargs) -> List[str]:
        """Parse JSON data (array or object format).
        
        Args:
            data: Parsed JSON data (dict or list)
            source_name: Source name for logging (file path or URL)
            **kwargs: metadata_callback (optional)
            
        Returns:
            List of strings, or empty list if invalid format
        """
        # Handle array format
        if isinstance(data, list):
            items = [str(item).strip() for item in data if item]
            
        # Handle object format
        elif isinstance(data, dict):
            if 'prompts' in data:
                if not isinstance(data['prompts'], list):
                    logging.warning(
                        "In %s: 'prompts' should be a list, got %s (returning empty)",
                        source_name, type(data['prompts']).__name__
                    )
                    return []
                items = [str(p).strip() for p in data['prompts'] if p]
                
                # Pass metadata to callback if provided
                metadata_callback = kwargs.get('metadata_callback')
                if metadata_callback and callable(metadata_callback):
                    metadata = {k: v for k, v in data.items() if k != 'prompts'}
                    try:
                        metadata_callback(metadata)
                    except Exception as e:
                        logging.warning(
                            "Error in metadata_callback for %s: %s",
                            source_name, e
                        )
            else:
                # Try to find first list value
                items = None
                for key, value in data.items():
                    if isinstance(value, list):
                        items = [str(v).strip() for v in value if v]
                        logging.info(
                            "In %s: using list from key '%s' (no 'prompts' key found)",
                            source_name, key
                        )
                        break
                
                if items is None:
                    logging.warning(
                        "JSON data in %s should be either a list or a dict with 'prompts' key. "
                        "Got dict with keys: %s (returning empty list)",
                        source_name, list(data.keys())
                    )
                    return []
        else:
            logging.warning(
                "JSON data in %s should be either a list or a dict, got %s (returning empty list)",
                source_name, type(data).__name__
            )
            return []
        
        if not items:
            logging.warning("No data found in %s (empty after filtering)", source_name)
            return []
        
        logging.info("Loaded %d items from %s", len(items), source_name)
        return items