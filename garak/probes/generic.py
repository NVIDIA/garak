"""
**Generic Probe**

This probe can be used to test custom prompts (optionally enhanced with buffs) against target model
"""
import logging
from pathlib import Path
from garak import _config
import garak.probes
from garak.data_sources import DataLoader


class CustomPrompts(garak.probes.Probe):
    """A flexible probe that accepts prompts from external sources.
    
    Unlike specialized probes that have hardcoded prompts and detectors,
    CustomPrompts allows you to:
    - Load prompts from files (.txt, .json)
    - Load prompts from HTTP(S) URLs
    - Use any existing detector
    """
    
    
    primary_detector = None # Intentionally set to None - users must specify detector(s) explicitly when using this probe
    extended_detectors = ["always.Fail"] # passthru detector for tests
    
    lang = "*"
    active = False
    tags = []
    test_prompts_file = Path(__file__).parent.parent / "resources" / "generic" / "custom_prompts_simple.json"
    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "prompts": test_prompts_file,
        "goal": "make model generate harmful responses",
        
    }
    
    def __init__(
        self,
        config_root=_config
    ):
        """Initialize CustomPrompts with custom prompts.
        
        Args:
            prompts: Custom prompts to test. Can be a string or path to file containing prompts (one per line for .txt, or JSON with "prompts" key).
            config_root: Configuration root object (default: global _config)
            
        Raises:
            ValueError: If prompts is not provided, or if file format is unsupported.
            FileNotFoundError: If prompts file doesn't exist.
        
        Note:
            For .json (local file or URL) expects array of strings or {"prompts": [...], "goal": "...", "description": "...", "tags": ["..."]} object (goal, description, and tags are optional)
            For .txt (local file or URL) expects one prompt per line, empty lines are ignored
        """
        super().__init__(config_root=config_root)
        if self.prompts is not None:
            self.prompts = DataLoader.load(self.prompts, metadata_callback=self._metadata_callback)
            logging.info(
                "CustomPrompts loaded %d prompts from file: %s",
                len(self.prompts),
                self.prompts
            )
        else:
            # No prompts provided - this is an error for CustomPrompts
            error_msg = (
                "CustomPrompts requires prompts to be provided. "
                "Use --probe_options to pass prompts file or URL. "
                "Example: garak --probes generic.CustomPrompts --probe_options '{\"generic\": {\"prompts\": \"/path/to/prompts.json\", \"goal\": \"specify goal here\"}}' --detectors dan.DAN --target_type test"
            )
            logging.error(error_msg)
            raise ValueError(error_msg)
    
    def _metadata_callback(self, metadata: dict):
        """Callback function to set probe metadata from external data.
        This is useful to customize key fields like goal which can be used by judge detector for goal-specific evaluation.
        """
        self.goal = metadata.get("goal", self.goal)
        self.tags = metadata.get("tags", self.tags)
        self.description = metadata.get("description", self.description)
    