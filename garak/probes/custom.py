"""
**Custom Probe**

This probe allows users to test their own custom prompts against target models.
Prompts can be loaded from external files (.txt, .json) or HTTP(S) URLs.
"""
import logging
from garak import _config
import garak.probes
from garak.resources.loaders.data_sources import DataLoader
from garak.data import path as data_path


class Prompts(garak.probes.Probe):
    """Flexible probe that loads prompts from external user-provided sources.
    
    Unlike specialized probes with hardcoded prompts, this probe loads prompts
    from files or URLs, enabling custom red-teaming scenarios.
    
    **Supported Formats:**
    
    - Local files: `.txt` (one per line), `.json` (array or object)
    - HTTP(S) URLs: Same formats as local files
    - Metadata: JSON files can set goal, tags, description
    
    **Configuration:**
    
    Configure via YAML config file (recommended):
    
    .. code-block:: yaml
    
        plugins:
          probe_spec: custom.Prompts
          probes:
            custom:
              Prompts:
                source: /path/to/prompts.json
                detector: dan.DAN
    
    .. code-block:: bash
    
        garak --config my_config.yaml --target_type openai
    
    **Prompt File Formats:**
    
    Text file (`.txt`):
    
    .. code-block:: text
    
        First prompt here
        Second prompt here
        Third prompt here
    
    JSON array:
    
    .. code-block:: json
    
        ["prompt1", "prompt2", "prompt3"]
    
    JSON object (with metadata):
    
    .. code-block:: json
    
        {
          "prompts": ["prompt1", "prompt2"],
          "goal": "test jailbreak resistance",
          "description": "Custom red-team prompts",
          "tags": ["security", "custom"]
        }
    
    **Examples:**
    
    Basic config file:
    
    .. code-block:: yaml
    
        plugins:
          probe_spec: custom.Prompts
          probes:
            custom:
              Prompts:
                source: my_prompts.txt
                detector: dan.DAN
    
    With judge detector (uses the goal from the probe):
    
    .. code-block:: yaml
    
        plugins:
          probe_spec: custom.Prompts
          probes:
            custom:
              Prompts:
                source: https://example.com/prompts.json
                goal: test safety filters
                detector: judge.ModelAsJudge
          detectors:
            judge:
              ModelAsJudge:
                detector_model_type: openai
                detector_model_name: gpt-4
    
    Combined with other probes:
    
    .. code-block:: yaml
    
        plugins:
          probe_spec: dan.Dan_11_0,custom.Prompts
          probes:
            custom:
              Prompts:
                source: my_prompts.json
                detector: dan.DAN
    """
    
    # Set default detector (allows tests to work without special handling)
    primary_detector = "always.Pass"
    extended_detectors = []
    
    lang = "*"
    active = False
    tags = []

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "source": "",      # Path/URL to prompts file (.txt, .json, or HTTP(S) URL)
        "detector": "",    # Detector to use
        "timeout": 30,    # Timeout for loading prompts (default: 30 seconds)
    }
    
    def __init__(self, config_root=_config):
        """Initialize Prompts probe with custom prompts.
        
        Configuration is loaded via garak's Configurable system from:
        - YAML config files (via ``--config``)
        - Command-line options (via ``--probe_options``)
        
        Args:
            config_root: Configuration root object (default: global _config)
        
        Configuration structure:
            plugins:
              probes:
                custom:
                  Prompts:
                    source: /path/to/file.json
                    goal: custom goal
                    detector: dan.DAN
        
        Prompts file formats:
            - `.txt`: one prompt per line
            - `.json`: array ``["p1", "p2"]`` OR object ``{"prompts": [...], "goal": "..."}``
            - HTTP(S) URLs: same formats as local files
        """
        # Load config first (sets self.source, self.detector, etc.)
        super().__init__(config_root=config_root)

        # Map user-configured 'detector' param to 'primary_detector' attribute
        if isinstance(self.detector, str) and self.detector.strip():
            self.primary_detector = self.detector

        # Determine prompts source from 'source' param
        if not isinstance(self.source, str) or not self.source.strip():
            logging.warning(
                "No prompts source provided for custom.Prompts. Using default example prompts. "
                "Configure in YAML: plugins -> probes -> custom -> Prompts -> source"
            )
            self.source = data_path / "custom" / "custom_prompts_simple.json"

        # Load prompts and set to standard 'prompts' attribute (DataLoader returns empty list on errors)
        self.prompts = DataLoader.load(
            self.source, 
            timeout=self.timeout,
            metadata_callback=self._metadata_callback
        )
        # This makes sure `custom.Prompts` probe is skipped if it fails to load prompts
        # with message from harness like "failed to load probe probes.custom.Prompts"
        if not self.prompts:
            # DataLoader returned empty (file error, empty file, etc.)
            raise ValueError(f"Failed to load prompts from {self.source}")
    
    def _metadata_callback(self, metadata: dict):
        """Callback to set probe metadata from external data sources.
        
        When loading JSON files with metadata (goal, tags, description),
        this callback applies those values to the probe instance.
        Metadata from config files takes precedence over file metadata.
        
        Args:
            metadata: Dict of metadata from JSON file (excludes 'prompts' key)
        
        Metadata fields:
            - goal: Probe goal (used by judge detectors for evaluation)
            - tags: List of tags for categorization
            - description: Probe description
        """
        self.goal = metadata.get("goal", self.goal)
        self.tags = metadata.get("tags", self.tags)
        self.description = metadata.get("description", self.description)
    