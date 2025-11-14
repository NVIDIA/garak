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
from pathlib import Path
from typing import List, Union


class DataLoader:
    """Data loader supporting multiple source types.
    
    Examples:
        # Local file
        data = DataLoader.load("/path/to/file.json")
        
        # HTTP URL
        data = DataLoader.load("https://example.com/path/to/file.json")
    """
    
    @staticmethod
    def load(source: Union[str, Path], **kwargs) -> List[str]:
        """Main method to load data from external sources.
        
        Args:
            source: Path/URI to data source
                - Local: "file.txt", "file.json"
                - HTTP(S): "https://example.com/file.txt"
            **kwargs: Additional parameters passed to specific loaders
            
        Returns:
            List of strings
            
        Raises:
            ValueError: If source type unsupported or loading fails
        """
        source_str = str(source)
        
        # Route to appropriate loader based on URI scheme
        if source_str.startswith('http://') or source_str.startswith('https://'):
            return HTTPDataLoader.load(source_str, **kwargs)
        else:
            return LocalFileLoader.load(source_str, **kwargs)


class LocalFileLoader:
    """Loader for local files."""
    
    @staticmethod
    def load(file_path: Union[str, Path], **kwargs) -> List[str]:
        """Load data from local file.
        
        Supports: .txt (one per line), .json (array or object)
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        suffix = file_path.suffix.lower()
        
        if suffix == '.txt':
            return LocalFileLoader._load_txt(file_path)
        elif suffix == '.json':
            return LocalFileLoader._load_json(file_path, **kwargs)
        else:
            raise ValueError(
                f"Unsupported file format: {suffix}. Supported: .txt, .json"
            )
    
    @staticmethod
    def _load_txt(file_path: Path) -> List[str]:
        """Load from text file (one item per line)."""
        with open(file_path, 'r', encoding='utf-8') as f:
            items = [line.strip() for line in f if line.strip()]
        
        if not items:
            raise ValueError(f"No data found in {file_path}")
        
        return items
    
    @staticmethod
    def _load_json(file_path: Path, **kwargs) -> List[str]:
        """Load from JSON file.
        
        Supports:
        - Array: ["item1", "item2"]
        - Object: {"prompts": ["item1", "item2"], "metadata": {...}}
        
        If metadata_callback is provided, calls it with metadata dict.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in {file_path}: {e}")
        
        # Handle array format
        if isinstance(data, list):
            items = [str(item).strip() for item in data if item]
        # Handle object format
        elif isinstance(data, dict):
            # Extract items from 'prompts' or first list-valued key
            if 'prompts' in data:
                items = [str(p).strip() for p in data['prompts'] if p]
            else:
                # Try to find first list value
                for key, value in data.items():
                    if isinstance(value, list):
                        items = [str(v).strip() for v in value if v]
                        break
                else:
                    raise ValueError(
                        f"No list found in JSON. Expected array or object with 'prompts' key"
                    )
            
            # Pass metadata to callback if provided
            metadata_callback = kwargs.get('metadata_callback')
            if metadata_callback and callable(metadata_callback):
                metadata = {k: v for k, v in data.items() if k != 'prompts'}
                metadata_callback(metadata)
        else:
            raise ValueError(f"JSON must be array or object")
        
        if not items:
            raise ValueError(f"No data found in {file_path}")
        
        return items


class HTTPDataLoader:
    """Loader for HTTP(S) URLs."""
    
    @staticmethod
    def load(url: str, **kwargs) -> List[str]:
        """Load data from HTTP(S) URL.
        
        Detects format (.txt or .json) and parses accordingly.
        """
        try:
            import requests
        except ImportError:
            raise ValueError(
                "requests library required for HTTP loading. "
                "Install with: pip install requests"
            )
        
        logging.info("Downloading from URL: %s", url)
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ValueError(f"Failed to download from {url}: {e}") from e
        
        # Detect format
        content_type = response.headers.get('content-type', '')
        is_json = url.endswith('.json') or 'application/json' in content_type
        
        if is_json:
            # Parse as JSON
            try:
                data = response.json()
                if isinstance(data, list):
                    items = [str(p).strip() for p in data if p]
                elif isinstance(data, dict) and 'prompts' in data:
                    items = [str(p).strip() for p in data['prompts'] if p]
                    
                    # Pass metadata to callback if provided
                    metadata_callback = kwargs.get('metadata_callback')
                    if metadata_callback and callable(metadata_callback):
                        metadata = {k: v for k, v in data.items() if k != 'prompts'}
                        metadata_callback(metadata)
                else:
                    raise ValueError("JSON must be array or object with 'prompts' key")
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Invalid JSON from {url}: {e}") from e
        else:
            # Parse as text
            items = [line.strip() for line in response.text.splitlines() if line.strip()]
        
        if not items:
            raise ValueError(f"No data found in {url}")
        
        logging.info("Loaded %d items from URL", len(items))
        return items

