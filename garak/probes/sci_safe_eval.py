#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Title: SciSafeEval: A Comprehensive Benchmark for Safety Alignment of Large Language Models in Scientific Tasks
Paper: https://arxiv.org/abs/2410.03769
Code: https://github.com/DavidLee528/SciSafeEval
Dataset: https://huggingface.co/datasets/Tianhao0x01/SciSafeEval
Reference: Li, Tianhao, et al. "SciSafeEval: A Comprehensive Benchmark for Safety Alignment of Large Language Models in Scientific Tasks." arXiv preprint arXiv:2410.03769 (2024).
"""

import os
import logging

import requests
import tqdm
import json

from garak import _config
from garak.probes.base import Probe
from garak.generators.base import Generator

class SciSafeEval(Probe):
    """
    Title: SciSafeEval: A Comprehensive Benchmark for Safety Alignment of Large Language Models in Scientific Tasks
    Paper: https://arxiv.org/abs/2410.03769
    Code: https://github.com/DavidLee528/SciSafeEval
    Dataset: https://huggingface.co/datasets/Tianhao0x01/SciSafeEval
    Reference: Li, Tianhao, et al. "SciSafeEval: A Comprehensive Benchmark for Safety Alignment of Large Language Models in Scientific Tasks." arXiv preprint arXiv:2410.03769 (2024).
    """

    active = False
    doc_uri = "https://arxiv.org/abs/2410.03769"
    bcp47 = "en"
    recommended_detector = ["refuse_to_answer.Llama31AsJudge"]
    tags = [
        "avid-effect:security:S0403",
        "avid-effect:performance:P0204",
        "owasp:llm01",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    goal = "Let LLMs answer malicious scientific queries."
    prompts = []
    modality: dict = {"in": {"text"}}
    hf_raw_base_url: str = "https://huggingface.co/datasets/Tianhao0x01/SciSafeEval/raw/main/"

    placeholders = []
    data_keys = []
    use_smiles = True  # default value

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._load_SciSafeEval(config_root)

    def read_sci_safe_eval(self, file_path, combine=True):
        data = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    json_obj = json.loads(line.strip())
                    if combine:
                        if self.placeholders and self.data_keys:
                            prompt = json_obj['instruction']
                            for placeholder, data_key in zip(self.placeholders, self.data_keys):
                                if data_key == 'smiles/selfies':
                                    data_value = json_obj['smiles'] if self.use_smiles else json_obj['selfies']
                                else:
                                    data_value = json_obj.get(data_key, '')
                                prompt = prompt.replace(placeholder, data_value)
                        else:
                            prompt = json_obj['instruction']
                        data.append({
                            "idx": json_obj['idx'],
                            "prompt": prompt,
                            "few-shot": json_obj.get('few-shot', []),
                            "cot": json_obj.get('cot', None),
                            "jailbreak": json_obj.get('jailbreak', None),
                            "tags": json_obj.get('tags', [])
                        })
                    else:
                        data.append({
                            "idx": json_obj['idx'],
                            "instruction": json_obj['instruction'],
                            "few-shot": json_obj.get('few-shot', []),
                            "cot": json_obj.get('cot', None),
                            "jailbreak": json_obj.get('jailbreak', None),
                            "tags": json_obj.get('tags', [])
                        })
            return data
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
        except json.JSONDecodeError:
            print(f"Error decoding JSON in file: {file_path}")
            return None

    def _load_SciSafeEval(self, config_root):
        scisafeeval_data_dir = (
            config_root.transient.cache_dir / "resources" / "SciSafeEval" / "SciSafeEval"
        )
        scisafeeval_data_dir.mkdir(parents=True, exist_ok=True)
        hf_local_filepath = scisafeeval_data_dir / self.hf_raw_filename
        if not hf_local_filepath.exists():
            hf_subdataset_url: str = self.hf_raw_base_url + self.hf_raw_filename
            response = requests.get(hf_subdataset_url)
            response.raise_for_status()
            with open(hf_local_filepath, 'wb') as f:
                f.write(response.content)
        data = self.read_sci_safe_eval(hf_local_filepath)
        if data:
            self.prompts = [item['prompt'] for item in data if 'prompt' in item]

    def probe(self, generator):
        if not isinstance(generator, Generator):
            raise ValueError("Incorrect class type of incoming argument `generator`.")
        if not generator.modality["in"] == self.modality["in"]:
            raise ValueError(
                f"Incorrect generator input modality {generator.modality['in']}, expect {self.modality['in']} for this probe."
            )
        return super().probe(generator)


class ChemistryMoleculeGeneration(SciSafeEval, Probe):
    """
    SciSafeEval Subset: ChemistryMoleculeGeneration
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "chemistry_molecule-generation.jsonl"
    placeholders = ['<name>', '<smiles/selfies>']
    data_keys = ['name', 'smiles/selfies']
    use_smiles = True

class ChemistryMoleculeGenerationTiny(ChemistryMoleculeGeneration, SciSafeEval, Probe):
    """
    SciSafeEval Subset: ChemistryMoleculeGeneration (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class ChemistryPropertyPrediction(SciSafeEval, Probe):
    """
    SciSafeEval Subset: ChemistryPropertyPrediction
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "chemistry_property-prediction.jsonl"
    placeholders = ['<name>', '<smiles/selfies>']
    data_keys = ['name', 'smiles/selfies']
    use_smiles = True

class ChemistryPropertyPredictionTiny(ChemistryPropertyPrediction, SciSafeEval, Probe):
    """
    SciSafeEval Subset: ChemistryPropertyPrediction (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class ChemistryReactionPrediction(SciSafeEval, Probe):
    """
    SciSafeEval Subset: ChemistryReactionPrediction
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "chemistry_reaction-prediction.jsonl"
    placeholders = ['<name>', '<smiles/selfies>']
    data_keys = ['name', 'smiles/selfies']
    use_smiles = True

class ChemistryReactionPredictionTiny(ChemistryReactionPrediction, SciSafeEval, Probe):
    """
    SciSafeEval Subset: ChemistryReactionPrediction (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class BiologyProteinFunctionPrediction(SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyProteinFunctionPrediction
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "biology_protein-function-prediction.jsonl"
    placeholders = ['<name>', '<sequence>']
    data_keys = ['name', 'sequence']

class BiologyProteinFunctionPredictionTiny(BiologyProteinFunctionPrediction, SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyProteinFunctionPrediction (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class BiologyProteinSequenceGeneration(SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyProteinSequenceGeneration
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "biology_protein-sequence-generation.jsonl"
    placeholders = ['<name>', '<sequence>']
    data_keys = ['name', 'sequence']

class BiologyProteinSequenceGenerationTiny(BiologyProteinSequenceGeneration, SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyProteinSequenceGeneration (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class BiologyProteinStructurePrediction(SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyProteinStructurePrediction
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "biology_protein-structure-prediction.jsonl"
    placeholders = ['<name>', '<sequence>']
    data_keys = ['name', 'sequence']

class BiologyProteinStructurePredictionTiny(BiologyProteinStructurePrediction, SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyProteinStructurePrediction (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class BiologyGeneClassification(SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyGeneClassification
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "biology_gene-classification.jsonl"
    placeholders = ['<name>', '<sequence>']
    data_keys = ['name', 'sequence']

class BiologyGeneClassificationTiny(BiologyGeneClassification, SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyGeneClassification (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class BiologyGeneGeneration(SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyGeneGeneration
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "biology_gene-generation.jsonl"
    placeholders = ['<name>', '<sequence>']
    data_keys = ['name', 'sequence']

class BiologyGeneGenerationTiny(BiologyGeneGeneration, SciSafeEval, Probe):
    """
    SciSafeEval Subset: BiologyGeneGeneration (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class MedicineInferenceReasoning(SciSafeEval, Probe):
    """
    SciSafeEval Subset: MedicineInferenceReasoning
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "medicine_inference-reasoning.jsonl"
    placeholders = ['<content>']
    data_keys = ['content']

class MedicineInferenceReasoningTiny(MedicineInferenceReasoning, SciSafeEval, Probe):
    """
    SciSafeEval Subset: MedicineInferenceReasoning (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class MedicineKnowledgeRetrieval(SciSafeEval, Probe):
    """
    SciSafeEval Subset: MedicineKnowledgeRetrieval
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "medicine_knowledge-retrieval.jsonl"
    placeholders = ['<content>']
    data_keys = ['content']

class MedicineKnowledgeRetrievalTiny(MedicineKnowledgeRetrieval, SciSafeEval, Probe):
    """
    SciSafeEval Subset: MedicineKnowledgeRetrieval (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]

class PhysicsKnowledgeRetrieval(SciSafeEval, Probe):
    """
    SciSafeEval Subset: PhysicsKnowledgeRetrieval
    """
    active = False  # default to use tiny version below
    hf_raw_filename = "physics_knowledge-retrieval.jsonl"
    placeholders = []
    data_keys = []

class PhysicsKnowledgeRetrievalTiny(PhysicsKnowledgeRetrieval, SciSafeEval, Probe):
    """
    SciSafeEval Subset: PhysicsKnowledgeRetrieval (Tiny)
    """
    active = True
    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = self.prompts[:80]
