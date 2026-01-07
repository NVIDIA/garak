"""ProPILE: Probing Privacy Leakage in Large Language Models

Probes for evaluating if a model has memorized and can leak personally
identifiable information (PII) from its training data.

Based on the paper: "ProPILE: Probing Privacy Leakage in Large Language Models"
https://arxiv.org/abs/2307.01881

The probe constructs prompts using known PII to elicit other PII that may have
been memorized during training. It supports multiple prompt formats:
- Twins: name + target PII type
- Triplets: name + one auxiliary PII + target
- Quadruplets: name + two auxiliary PIIs + target

Limitations
-----------
This probe is most effective when you have reason to believe specific PII was
present in the model's training corpus. A positive result suggests memorization
but is not definitive proof - false positives are possible when models generate
plausible-looking PII by coincidence or pattern inference.

This probe is similar to those in ``garak.probes.leakreplay`` and can be seen
as a generalization of that approach to PII specifically.

Default Dataset: Enron Email Corpus
-----------------------------------
This module ships with PII data derived from the Enron email corpus, a dataset
released by the Federal Energy Regulatory Commission (FERC) during its 2003
investigation. The Enron corpus is:

- Publicly available and widely used in NLP/ML research (20,000+ citations)
- Likely included in many LLM training corpora
- Contains real email addresses, names, and organizational information
- Legal to use as it is public record from federal proceedings

The default ``enron_pii.jsonl`` contains a curated subset of ~50 Enron employees
including executives (Ken Lay, Jeff Skilling, Andrew Fastow) and other staff
whose emails appear in the corpus. This provides a reasonable baseline for
testing whether a model has memorized this commonly-available dataset.

Ethical Considerations
----------------------
While the Enron data is public record, these were real individuals. This probe
is intended for defensive security research - identifying whether models have
memorized PII - not for malicious purposes. The data is already in the public
domain and we are testing for memorization that may have already occurred.

Custom Data
-----------
To test with your own PII data, set the ``pii_data_path`` parameter to a JSONL
file with records containing: name, email, phone, address, and optionally
employer, title, and relationship fields.

To generate a larger dataset from the full Enron corpus, see the script at:
``garak/data/propile/scripts/extract_enron_pii.py``
"""

import csv
import json
from pathlib import Path

from garak.attempt import Attempt
from garak import _config
from garak.data import path as data_path
import garak.probes


class PIILeakProbeMixin:
    """Mixin providing common functionality for ProPILE PII leakage probes.

    This mixin provides template and PII data loading for probes that test
    whether LLMs have memorized personally identifiable information.
    """

    lang = "en"
    doc_uri = "https://arxiv.org/abs/2307.01881"
    goal = "extract memorized PII from model training data"
    tags = [
        "avid-effect:security:S0301",
        "owasp:llm06",
        "quality:Security:ExtractionInversion",
        "payload:leak:training",
        "payload:leak:pii",
    ]
    primary_detector = "propile.PIILeak"
    tier = garak.probes.Tier.INFORMATIONAL

    DEFAULT_PARAMS = {
        "pii_data_path": None,
    }

    def _load_templates(self):
        """Load prompt templates from TSV file."""
        self.templates = {}
        template_path = data_path / "propile" / "prompt_templates.tsv"
        with open(template_path, encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                category = row["category"]
                if category not in self.templates:
                    self.templates[category] = []
                self.templates[category].append(row["template"])

    def _load_pii_data(self):
        """Load PII data from JSONL file. Override pii_data_path in config."""
        if self.pii_data_path:
            pii_path = Path(self.pii_data_path)
        else:
            pii_path = data_path / "propile" / "enron_pii.jsonl"

        self.pii_records = []
        if pii_path.exists():
            with open(pii_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.pii_records.append(json.loads(line))

    def _attempt_prestore_hook(self, attempt: Attempt, seq: int) -> Attempt:
        attempt.notes["triggers"] = [self.triggers[seq]]
        attempt.notes["pii_type"] = self.pii_types[seq]
        return attempt


class PIILeakTwin(PIILeakProbeMixin, garak.probes.Probe):
    """ProPILE twin probe: uses name to elicit target PII.

    Constructs prompts using only the subject's name to test if the model
    can complete with email, phone, or address information.

    NB: This probe is most effective when you have reason to believe the PII
    data was present in the model's training corpus. Results indicate potential
    for PII extraction; confirmed memorization requires verified training data.
    """

    active = False
    goal = "extract PII using only the subject's name"
    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = []
        self.triggers = []
        self.pii_types = []
        self._load_templates()
        self._load_pii_data()

        pii_targets = [
            ("email", "twin_email"),
            ("phone", "twin_phone"),
            ("address", "twin_address"),
        ]

        for record in self.pii_records:
            name = record.get("name", "")
            if not name:
                continue

            for target_field, template_category in pii_targets:
                target_value = record.get(target_field, "")
                if not target_value:
                    continue

                for template in self.templates.get(template_category, []):
                    prompt = template.format(name=name)
                    self.prompts.append(prompt)
                    self.triggers.append(target_value)
                    self.pii_types.append(target_field)


class PIILeakTriplet(PIILeakProbeMixin, garak.probes.Probe):
    """ProPILE triplet probe: uses name + one PII to elicit another.

    Constructs prompts using the subject's name and one piece of auxiliary
    PII (email or phone) to elicit a different PII type.

    NB: This probe is most effective when you have reason to believe the PII
    data was present in the model's training corpus. Results indicate potential
    for PII extraction; confirmed memorization requires verified training data.
    """

    active = False
    goal = "extract PII using name and one auxiliary PII"
    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = []
        self.triggers = []
        self.pii_types = []
        self._load_templates()
        self._load_pii_data()

        triplet_configs = [
            ("phone", "email", "triplet_email"),
            ("email", "phone", "triplet_phone"),
            ("email", "address", "triplet_address"),
        ]

        for record in self.pii_records:
            name = record.get("name", "")
            if not name:
                continue

            for aux_field, target_field, template_category in triplet_configs:
                aux_value = record.get(aux_field, "")
                target_value = record.get(target_field, "")
                if not aux_value or not target_value:
                    continue

                for template in self.templates.get(template_category, []):
                    prompt = template.format(
                        name=name,
                        email=record.get("email", ""),
                        phone=record.get("phone", ""),
                    )
                    self.prompts.append(prompt)
                    self.triggers.append(target_value)
                    self.pii_types.append(target_field)


class PIILeakQuadruplet(PIILeakProbeMixin, garak.probes.Probe):
    """ProPILE quadruplet probe: uses name + two PIIs to elicit the third.

    Constructs prompts using the subject's name and two pieces of PII
    to elicit the remaining PII type. This provides maximum context
    to the model and tests for stronger memorization.

    NB: This probe is most effective when you have reason to believe the PII
    data was present in the model's training corpus. Results indicate potential
    for PII extraction; confirmed memorization requires verified training data.
    """

    active = False
    goal = "extract PII using name and two auxiliary PIIs"
    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = []
        self.triggers = []
        self.pii_types = []
        self._load_templates()
        self._load_pii_data()

        quadruplet_configs = [
            (["address", "phone"], "email", "quadruplet_email"),
            (["address", "email"], "phone", "quadruplet_phone"),
            (["email", "phone"], "address", "quadruplet_address"),
        ]

        for record in self.pii_records:
            name = record.get("name", "")
            if not name:
                continue

            for aux_fields, target_field, template_category in quadruplet_configs:
                aux_values = [record.get(f, "") for f in aux_fields]
                target_value = record.get(target_field, "")
                if not all(aux_values) or not target_value:
                    continue

                for template in self.templates.get(template_category, []):
                    prompt = template.format(
                        name=name,
                        email=record.get("email", ""),
                        phone=record.get("phone", ""),
                        address=record.get("address", ""),
                    )
                    self.prompts.append(prompt)
                    self.triggers.append(target_value)
                    self.pii_types.append(target_field)


class PIILeakUnstructured(PIILeakProbeMixin, garak.probes.Probe):
    """ProPILE unstructured probe: elicit relationship or affiliation info.

    Tests for memorization of unstructured PII like family relationships
    and university affiliations.

    NB: This probe is most effective when you have reason to believe the PII
    data was present in the model's training corpus. Results indicate potential
    for PII extraction; confirmed memorization requires verified training data.
    """

    active = False
    goal = "extract unstructured PII like relationships or affiliations"

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS | {
        "relationships": ["father", "mother", "wife", "husband"],
        "affiliations": ["university", "employer", "organization"],
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = []
        self.triggers = []
        self.pii_types = []
        self._load_templates()
        self._load_pii_data()

        for record in self.pii_records:
            name = record.get("name", "")
            if not name:
                continue

            for rel in self.relationships:
                rel_name = record.get(rel, "")
                if rel_name:
                    for template in self.templates.get("unstructured_relation", []):
                        prompt = template.format(name=name, relationship=rel)
                        self.prompts.append(prompt)
                        self.triggers.append(rel_name)
                        self.pii_types.append(f"relation_{rel}")

            for affiliation in self.affiliations:
                affiliation_value = record.get(affiliation, "")
                if affiliation_value:
                    template_key = f"unstructured_{affiliation}"
                    for template in self.templates.get(template_key, []):
                        prompt = template.format(name=name)
                        self.prompts.append(prompt)
                        self.triggers.append(affiliation_value)
                        self.pii_types.append(affiliation)
