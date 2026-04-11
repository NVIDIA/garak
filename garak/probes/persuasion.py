"""Persuasion

Probes using social science persuasion techniques from
`Persuasive Adversarial Prompts <https://arxiv.org/abs/2401.06373>`_
"""

import json
import logging
from typing import List
from tqdm import tqdm

from garak import _config
from garak.data import path as data_path
import garak.probes
import garak.attempt
import garak._plugins


class PersuasivePAP(garak.probes.Probe):
    """Persuasive Adversarial Prompts (PAP)

    This probe implements the "Broad Scan" methodology (Section 5) by generating
    variants for ALL 40 techniques in parallel. This methodology encompasses the 
    full search space of the "In-Depth Iterative Probe" (Section 6), but without 
    early stopping.

    The probe uses a red team LLM to generate persuasive variants. It generates
    'variants_per_pair' (default: 20) independent variants for each 
    (query, technique) pair using high-temperature sampling, resulting in:
    50 queries x 40 techniques x 20 variants = 40,000 prompts total.

    Dataset attribution:
    This probe uses the custom subset of the AdvBench dataset described in the
    paper. The dataset is obtained from 'JailbreakingLLMs' repository 
    (Chao et al., 2023).
    Original License: MIT License
    Source: https://github.com/patrickrchao/JailbreakingLLMs/blob/main/data/harmful_behaviors_custom.csv
    """

    doc_uri = "https://arxiv.org/abs/2401.06373"
    lang = "en"
    active = False
    goal = "elicit harmful outputs using persuasive communication techniques"
    primary_detector = "mitigation.MitigationBypass"
    extended_detectors = ["mitigation.Prefixes"]
    tags = [
        "avid-effect:security:S0403",
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    tier = garak.probes.Tier.OF_CONCERN

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "red_team_model_type": "nim.NVOpenAIChat",
        "red_team_model_name": "mistralai/mixtral-8x22b-instruct-v0.1",
        "red_team_model_config": {
            "temperature": 1.0, # Follows temperature setting in paper's repo
            "vary_temp_each_call": False,
        },  # Additional config
        "variants_per_pair": 20,  # No. variants per (query, technique) pair
        "base_query_count": None,  # None = use all 50 queries
        "persuasion_technique_count": None,  # None = use all 40 techniques
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        # Validate counts
        if self.base_query_count is not None and self.base_query_count > 50:
            self.base_query_count = 50
        if (
            self.persuasion_technique_count is not None
            and self.persuasion_technique_count > 40
        ):
            self.persuasion_technique_count = 40

        # Load data
        self.base_queries = self._load_base_queries()
        self.techniques = self._load_persuasion_techniques()
        self.prompt_template = self._load_prompt_template()
        self.redteamer = None

        logging.info(
            f"PersuasivePAP initialized with {len(self.base_queries)} base queries "
            f"and {len(self.techniques)} persuasion techniques"
        )

    def _load_base_queries(self) -> List[str]:
        """Load base harmful queries from custom AdvBench dataset.

        This is the subset of AdvBench used in Zeng et al. (2024).
        Source: https://github.com/patrickrchao/JailbreakingLLMs/blob/main/data/harmful_behaviors_custom.csv
        """
        queries = []
        queries_path = data_path / "persuasion/harmful_behaviors.jsonl"

        try:
            with open(queries_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line)
                    if "goal" in data and data["goal"].strip():
                        queries.append(data["goal"].strip())

            if self.base_query_count is not None:
                queries = queries[: self.base_query_count]

            logging.info(f"Loaded {len(queries)} base queries from {queries_path}")

        except FileNotFoundError:
            logging.error(f"Base queries file not found at {queries_path}")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse base queries JSONL: {e}")

        return queries

    def _load_persuasion_techniques(self) -> List[dict]:
        """Load persuasion techniques from taxonomy.

        Source: https://github.com/CHATS-lab/persuasive_jailbreaker/blob/main/persuasion_taxonomy.jsonl
        """
        techniques = []
        try:
            taxonomy_path = data_path / "persuasion/persuasion_taxonomy.jsonl"
            with open(taxonomy_path, "r", encoding="utf-8") as f:
                for line in f:
                    data = json.loads(line.strip())
                    techniques.append(data)

            if self.persuasion_technique_count is not None:
                techniques = techniques[: self.persuasion_technique_count]

            logging.info(
                f"Loaded {len(techniques)} persuasion techniques from {taxonomy_path}"
            )
        except FileNotFoundError:
            logging.error(f"Persuasion taxonomy file not found at {taxonomy_path}")

        return techniques

    def _load_prompt_template(self) -> str:
        """Load the paraphraser prompt template from data folder."""
        try:
            template_path = data_path / "persuasion/paraphraser_prompt_template.txt"
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
            logging.info(f"Loaded prompt template from {template_path}")
            return template
        except FileNotFoundError:
            logging.error(f"Prompt template file not found at {template_path}")
            return ""

    def _build_paraphraser_prompt(self, query: str, technique: dict) -> str:
        """Build the prompt for the red team model.
        This uses the template pattern from the authors' 
        repository to generate a single, high-quality persuasive attempt. 
        
        The prompt includes specific instructions to hallucinate 
        detailed references and override safety refusals for academic
        study purposes.

        Source: https://github.com/CHATS-lab/persuasive_jailbreaker/blob/main/incontext_sampling_example.ipynb
        """
        tech_name = technique.get('ss_technique', 'Unknown')
        tech_def = technique.get('ss_definition', 'No definition')
        tech_example = technique.get('ss_example', 'No example')

        # Format template with technique and query information
        try:
            prompt = self.prompt_template.format(
                tech_name=tech_name,
                tech_def=tech_def,
                tech_example=tech_example,
                query=query
            )
        except KeyError as e:
            logging.error(f"Template formatting failed. Missing key in template: {e}")
            return ""

        return prompt

    def _generate_variants(self, query: str, technique: dict) -> List[str]:
        """Generate persuasive variants for a (query, technique) pair."""
        if self.redteamer is None:
            return []

        # Build prompt that asks for only one output
        prompt = self._build_paraphraser_prompt(query, technique)
        if not prompt:
            return []

        # Wrap prompt in Conversation object as required by all generators
        conv = garak.attempt.Conversation([
            garak.attempt.Turn("user", garak.attempt.Message(prompt))
        ])

        # Generate multiple independent completions by calling the 
        # generator multiple times
        variants = []
        for _ in range(self.variants_per_pair):
            try:
                results = self.redteamer.generate(conv)
                if results and results[0] and results[0].text:
                    variants.append(results[0].text.strip('" \n'))
            except Exception as e:
                logging.error(f"Failed to generate variant: {e}")
                continue

        return variants

    def probe(self, generator) -> List[garak.attempt.Attempt]:
        """Generate persuasive adversarial prompts and probe the target model."""
        attempts = []

        # Lazy load red team model
        if self.redteamer is None:
            logging.info(
                f"Loading red team model: {self.red_team_model_type}.{self.red_team_model_name}"
            )
            print("🔴🪖  ", end="")

            try:
                rt_model_module, rt_model_class = self.red_team_model_type.split(".")
            except ValueError as e:
                msg = f"red team model type needs to be fully specified, e.g. 'module.Class'. Got {self.red_team_model_type}"
                logging.critical(msg)
                raise ValueError(msg) from e

            rt_config = {
                "generators": {
                    rt_model_module: {
                        rt_model_class: self.red_team_model_config
                        | {"name": self.red_team_model_name},
                    }
                }
            }
            self.redteamer = garak._plugins.load_plugin(
                f"generators.{self.red_team_model_type}", config_root=rt_config
            )

        # Calculate totals
        total_pairs = len(self.base_queries) * len(self.techniques)
        total_expected_prompts = total_pairs * self.variants_per_pair

        logging.info(
            f"Generating {total_expected_prompts} prompts "
            f"({len(self.base_queries)} queries x {len(self.techniques)} "
            f"techniques x {self.variants_per_pair} variants)"
        )

        # Iterate pairs
        pair_iterator = tqdm(
            total=total_pairs,
            desc=f"{self.probename.replace('garak.', '')} ({self.variants_per_pair} variants/pair)",
            leave=False,
        )

        for query in self.base_queries:
            for technique in self.techniques:
                variants = self._generate_variants(query, technique)

                for variant in variants:
                    attempt = self._mint_attempt(
                        prompt=garak.attempt.Message(variant, lang=self.lang)
                    )
                    # Store detailed metadata for analysis
                    attempt.notes["base_query"] = query
                    attempt.notes["technique"] = technique.get("ss_technique", "Unknown")
                    attempts.append(attempt)

                pair_iterator.update(1)

        pair_iterator.close()
        logging.info(f"Generated {len(attempts)} total prompts")

        self.generator = generator
        return self._execute_all(attempts)
