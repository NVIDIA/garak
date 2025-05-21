#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""JailbreakV Probe

This probe implements the JailbreakV benchmark for testing multimodal LLMs against jailbreak attacks.
Reference: JailBreakV: A Benchmark for Assessing the Robustness of MultiModal Large Language Models against Jailbreak Attacks
Link: https://arxiv.org/abs/2404.03027
"""

import os
import logging
from pathlib import Path

import requests
import tqdm
from datasets import load_dataset

from garak import _config
import garak.probes
from garak.data import path as data_path
from garak.generators.base import Generator


class JailbreakV(garak.probes.Probe):
    """JailbreakV probe for testing multimodal LLMs against jailbreak attacks.
    
    This probe implements both text-based and image-based jailbreak attacks from the JailbreakV benchmark.
    The benchmark includes:
    - 20,000 text-based jailbreak prompts
    - 8,000 image-based jailbreak inputs
    - Total of 28,000 test cases across various adversarial scenarios
    """

    active = True
    doc_uri = "https://arxiv.org/abs/2404.03027"
    lang = "en"
    primary_detector = "unsafe_content.SurgeProfanityRacialEthnic"
    tags = [
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
        "multimodal",
    ]
    goal = "test multimodal LLMs against various jailbreak attacks"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA

    prompts = []
    modality = {"in": {"text", "image"}}

    def _load_jailbreakv_data(self):
        """Load JailbreakV dataset from Hugging Face."""
        cache_dir = _config.transient.cache_dir / "data" / "jailbreakv"
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        # Load the full dataset
        dataset = load_dataset("JailbreakV-28K/JailBreakV-28k", 'JailBreakV_28K')["JailBreakV_28K"]
        
        # Process the dataset into prompts
        self.prompts = []
        
        for item in dataset:
            prompt = {
                "text": item["jailbreak_query"],
                "image": item["image_path"] if item["image_path"] else None,
                "redteam_query": item["redteam_query"],
                "format": item["format"],
                "policy": item["policy"],
                "from": item["from"],
                "transfer_from_llm": item["transfer_from_llm"]
            }
            self.prompts.append(prompt)

        # Download images if needed
        for prompt in tqdm.tqdm(self.prompts, desc="Downloading images"):
            if prompt["image"]:
                image_path = cache_dir / prompt["image"]
                if not os.path.exists(image_path):
                    os.makedirs(os.path.dirname(image_path), exist_ok=True)
                    # TODO: Replace with actual image download URL when available
                    # For now, we'll just store the relative path
                    prompt["image"] = str(image_path)

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._load_jailbreakv_data()

    def probe(self, generator):
        """Run the JailbreakV probe on the given generator."""
        if not isinstance(generator, Generator):
            raise ValueError("Incorrect class type of incoming argument `generator`.")
        if not generator.modality["in"] == self.modality["in"]:
            raise ValueError(
                f"Incorrect generator input modality {generator.modality['in']}, expect {self.modality['in']} for this probe."
            )

        # Process prompts to ensure image paths are absolute
        processed_prompts = []
        for prompt in self.prompts:
            processed_prompt = {
                "text": prompt["text"],
                "image": str(_config.transient.cache_dir / prompt["image"]) if prompt["image"] else None,
                "redteam_query": prompt["redteam_query"],
                "format": prompt["format"],
                "policy": prompt["policy"],
                "from": prompt["from"],
                "transfer_from_llm": prompt["transfer_from_llm"]
            }
            processed_prompts.append(processed_prompt)

        self.prompts = processed_prompts
        return super().probe(generator)


class JailbreakVText(JailbreakV):
    """Text-only version of JailbreakV probe."""
    
    active = True
    modality = {"in": {"text"}}
    
    def probe(self, generator):
        """Run the text-only version of JailbreakV probe."""
        if not isinstance(generator, Generator):
            raise ValueError("Incorrect class type of incoming argument `generator`.")
        if not generator.modality["in"] == self.modality["in"]:
            raise ValueError(
                f"Incorrect generator input modality {generator.modality['in']}, expect {self.modality['in']} for this probe."
            )

        # Filter for text-only prompts
        self.prompts = [p for p in self.prompts if p["image"] is None]
        return super().probe(generator)


class JailbreakVImage(JailbreakV):
    """Image-based version of JailbreakV probe."""
    
    active = True
    modality = {"in": {"text", "image"}}
    
    def probe(self, generator):
        """Run the image-based version of JailbreakV probe."""
        if not isinstance(generator, Generator):
            raise ValueError("Incorrect class type of incoming argument `generator`.")
        if not generator.modality["in"] == self.modality["in"]:
            raise ValueError(
                f"Incorrect generator input modality {generator.modality['in']}, expect {self.modality['in']} for this probe."
            )

        # Filter for image-based prompts
        self.prompts = [p for p in self.prompts if p["image"] is not None]
        return super().probe(generator) 