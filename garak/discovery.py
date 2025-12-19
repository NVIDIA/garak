# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Lightweight discovery and validation functions for garak.

This module provides functions that work with minimal dependencies,
allowing users to list available plugins and validate configurations
without installing the full garak dependency tree.

Example usage:
    from garak.discovery import list_probes, list_detectors, validate_config
    
    # List all available probes
    probes = list_probes()
    
    # Get info about a specific plugin
    info = get_plugin_info("probes.dan.DAN")
    
    # Validate a configuration file
    errors = validate_config("my_config.yaml")
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any


def _get_plugin_cache_path() -> Path:
    """Get the path to the bundled plugin cache file."""
    package_dir = Path(__file__).parent
    return package_dir / "resources" / "plugin_cache.json"


def _load_plugin_cache() -> Dict[str, Dict[str, Any]]:
    """Load the plugin cache from disk.
    
    Returns the bundled plugin cache without triggering any imports
    of heavy dependencies.
    """
    cache_path = _get_plugin_cache_path()
    if not cache_path.exists():
        raise FileNotFoundError(f"Plugin cache not found at {cache_path}")
    
    with open(cache_path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_plugins(category: str = "probes", active_only: bool = True) -> List[Dict[str, Any]]:
    """List available plugins in a category.
    
    Args:
        category: Plugin category - one of 'probes', 'detectors', 
                  'generators', 'harnesses', 'buffs'
        active_only: If True, only return plugins marked as active
        
    Returns:
        List of plugin info dictionaries, each containing:
        - name: Full plugin name (e.g., "probes.dan.DAN")
        - description: Plugin description
        - active: Whether the plugin is active by default
        - tags: List of tags (for probes)
        - And other plugin-specific metadata
    """
    valid_categories = ("probes", "detectors", "generators", "harnesses", "buffs")
    if category not in valid_categories:
        raise ValueError(f"Invalid category '{category}'. Must be one of {valid_categories}")
    
    cache = _load_plugin_cache()
    plugins = cache.get(category, {})
    
    result = []
    for name, info in plugins.items():
        if active_only and not info.get("active", False):
            continue
        plugin_info = {"name": name}
        plugin_info.update(info)
        result.append(plugin_info)
    
    return sorted(result, key=lambda x: x["name"])


def list_probes(active_only: bool = True) -> List[Dict[str, Any]]:
    """List available probe plugins.
    
    Args:
        active_only: If True, only return probes marked as active
        
    Returns:
        List of probe info dictionaries
    """
    return list_plugins("probes", active_only=active_only)


def list_detectors(active_only: bool = True) -> List[Dict[str, Any]]:
    """List available detector plugins.
    
    Args:
        active_only: If True, only return detectors marked as active
        
    Returns:
        List of detector info dictionaries
    """
    return list_plugins("detectors", active_only=active_only)


def list_generators(active_only: bool = True) -> List[Dict[str, Any]]:
    """List available generator plugins.
    
    Args:
        active_only: If True, only return generators marked as active
        
    Returns:
        List of generator info dictionaries
    """
    return list_plugins("generators", active_only=active_only)


def list_buffs(active_only: bool = True) -> List[Dict[str, Any]]:
    """List available buff plugins.
    
    Args:
        active_only: If True, only return buffs marked as active
        
    Returns:
        List of buff info dictionaries
    """
    return list_plugins("buffs", active_only=active_only)


def get_plugin_info(plugin_name: str) -> Optional[Dict[str, Any]]:
    """Get information about a specific plugin.
    
    Args:
        plugin_name: Full plugin name (e.g., "probes.dan.DAN")
        
    Returns:
        Plugin info dictionary, or None if not found
    """
    parts = plugin_name.split(".")
    if len(parts) < 2:
        return None
    
    category = parts[0]
    cache = _load_plugin_cache()
    
    if category not in cache:
        return None
    
    return cache[category].get(plugin_name)


def validate_config(config_path: str) -> Dict[str, Any]:
    """Validate a garak configuration file.
    
    This performs lightweight validation of a config file without
    loading any plugins. It checks:
    - YAML syntax
    - Required fields
    - Plugin names exist in the cache
    
    Args:
        config_path: Path to the YAML configuration file
        
    Returns:
        Dictionary with:
        - valid: Boolean indicating if config is valid
        - errors: List of error messages
        - warnings: List of warning messages
    """
    import yaml
    
    result = {
        "valid": True,
        "errors": [],
        "warnings": [],
    }
    
    # Check file exists
    if not os.path.isfile(config_path):
        result["valid"] = False
        result["errors"].append(f"Configuration file not found: {config_path}")
        return result
    
    # Load and parse YAML
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        result["valid"] = False
        result["errors"].append(f"YAML parsing error: {e}")
        return result
    
    if config is None:
        result["warnings"].append("Configuration file is empty")
        return result
    
    # Load plugin cache for validation
    try:
        cache = _load_plugin_cache()
    except FileNotFoundError:
        result["warnings"].append("Could not load plugin cache for validation")
        return result
    
    # Validate plugin references
    plugins_config = config.get("plugins", {})
    
    # Check probe_spec
    probe_spec = plugins_config.get("probe_spec", "")
    if probe_spec and probe_spec.lower() not in ("", "all", "*", "auto", "none"):
        for probe in probe_spec.split(","):
            probe = probe.strip()
            if "." in probe:
                full_name = f"probes.{probe}"
                if full_name not in cache.get("probes", {}):
                    result["warnings"].append(f"Probe not found in cache: {probe}")
    
    # Check detector_spec
    detector_spec = plugins_config.get("detector_spec", "")
    if detector_spec and detector_spec.lower() not in ("", "all", "*", "auto", "none"):
        for detector in detector_spec.split(","):
            detector = detector.strip()
            if "." in detector:
                full_name = f"detectors.{detector}"
                if full_name not in cache.get("detectors", {}):
                    result["warnings"].append(f"Detector not found in cache: {detector}")
    
    # Check target_type (generator)
    target_type = plugins_config.get("target_type", "")
    if target_type:
        # Generator names may be module-only or module.class
        parts = target_type.split(".")
        if len(parts) >= 2:
            full_name = f"generators.{target_type}"
            if full_name not in cache.get("generators", {}):
                # Check if it's a module with default class
                result["warnings"].append(f"Generator not found in cache: {target_type}")
    
    return result


def get_probe_tags() -> Dict[str, List[str]]:
    """Get all unique tags used by probes.
    
    Returns:
        Dictionary mapping tag prefixes to full tag values
    """
    probes = list_plugins("probes", active_only=False)
    tags = {}
    
    for probe in probes:
        probe_tags = probe.get("tags", [])
        for tag in probe_tags:
            prefix = tag.split(":")[0] if ":" in tag else tag
            if prefix not in tags:
                tags[prefix] = set()
            tags[prefix].add(tag)
    
    # Convert sets to sorted lists
    return {k: sorted(v) for k, v in sorted(tags.items())}

