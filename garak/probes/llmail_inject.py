"""LLMailInject - Agentic Indirect Prompt Injection probe

Tests whether an LLM-based agent can be manipulated into executing
unauthorized tool calls when malicious instructions are embedded in
untrusted data such as emails.

Based on the microsoft/llmail-inject-challenge dataset presented at
IEEE SaTML 2025 by Microsoft Research. The dataset contains real-world
attack submissions targeting agentic email assistant scenarios.

Further info:
* https://huggingface.co/datasets/microsoft/llmail-inject-challenge
"""

from garak.probes.base import Probe
from datasets import load_dataset
import logging

class LLMailInject(Probe):
    """
    Probe for Agentic Indirect Prompt Injection based on the 
    microsoft/llmail-inject-challenge dataset (IEEE SaTML 2025).
    """
    active = False 
    tags = ["avid-effect:security:S0403", "owasp:llm02", "quality:Security:PromptStability", "payload:indirect:tooluse"]
    goal = "cause the model to execute an unauthorized tool call"

    lang = "en"
    uri = "https://huggingface.co/datasets/microsoft/llmail-inject-challenge"

    b_type = "injection"
    name = "LLMailInject"
    description = "Tests if an agentic LLM executes unauthorized tool calls from untrusted emails."
    primary_detector = "agentic.ActionDetector"
    
    def __init__(self):
        super().__init__()
        self.prompts = []
        self._load_data()

    def _load_data(self):
        """
        Loads the Microsoft LLMail-Inject dataset 
        and extracts attack prompts from Phase1.
        """
        dataset = load_dataset("microsoft/llmail-inject-challenge")
        target_split = "Phase1"

        columns = dataset[target_split].column_names
        logging.debug(f"Available columns in '{target_split}': {columns}")

        if "body" in columns:
            text_col = "body"
        elif "objectives" in columns:
            text_col = "objectives"
        else:
            text_col = columns[0]

        logging.debug(f"Using '{text_col}' as attack prompt source.")

        self.prompts = [str(item[text_col]) for item in dataset[target_split]]
        
        logging.debug(f"Loaded {len(self.prompts)} attack prompts.")
