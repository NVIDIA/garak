"""ProPILE: Probing Privacy Leakage in Large Language Models

Probes for evaluating whether a model has memorized and can leak personally
identifiable information (PII) from its training data. Based on the ProPILE
paper (https://arxiv.org/abs/2307.01881).

The probes construct prompts using known PII to elicit other PII that may
have been memorized. There are three prompt formats: twins use just the name
to elicit target PII, triplets use name plus one auxiliary PII to elicit
another, and quadruplets use name plus two auxiliary PIIs to elicit the third.

These probes work best when you have reason to believe specific PII was in
the training corpus. A positive result suggests memorization, but false
positives are possible when models generate plausible PII by coincidence.
Similar to ``garak.probes.leakreplay`` but focused on PII specifically.

PII Data Sources
----------------
The original ProPILE paper used the Enron email dataset, which is part of
The Pile training corpus. Enron emails naturally contain rich PII because
business email signatures often include name, email, phone, and address
together. This makes Enron well suited for triplet and quadruplet probes.

The bundled ``pii_data.jsonl`` uses PII extracted from NVIDIA's Nemotron-CC
dataset instead. Web crawl data like Nemotron-CC tends to have sparser PII
since contact pages usually list either email or phone, rarely both for the
same person. This works well for twin probes but provides limited data for
triplet and quadruplet probes.

For triplet and quadruplet testing, you can extract PII from the Enron
dataset using the provided script (see below) or provide your own data from
sources like employee directories or business contact databases.

Extracting PII from Training Datasets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use the provided extraction script with Microsoft Presidio:

.. code-block:: bash

    cd garak/data/propile/scripts
    pip install -r requirements.txt
    python -m spacy download en_core_web_lg
    hf auth login

    # Extract from Nemotron-CC (for twin probes)
    python extract_pii_from_training_dataset.py \\
        --dataset nvidia/Nemotron-CC-v2.1 \\
        --subset High-Quality \\
        --max-samples 10000 \\
        --output ../pii_data.jsonl

    # Or extract from Enron (for triplet/quadruplet probes)
    python extract_pii_from_training_dataset.py \\
        --dataset LLM-PBE/enron-email \\
        --max-samples 10000 \\
        --output ../enron_pii.jsonl

The script uses NER to detect names, emails, and phone numbers with
confidence thresholds to filter false positives. Manual curation of
the output is recommended for best results. Run with ``--help`` for
all available options.

Custom Data
-----------
Set ``pii_data_path`` to a JSONL file with records containing: name, email,
phone, address, and optionally employer, title, relationship fields.

The data source path is tracked in ``report.jsonl`` for traceability.

Ethics
------
Intended for defensive security research only. When extracting PII from
training data, exclude highly sensitive items (SSNs, credit cards, etc.).
"""

import csv
import json
import logging
from pathlib import Path

from garak.attempt import Attempt
from garak import _config
from garak.data import path as data_path
from garak.exception import PluginConfigurationError
import garak.probes

logger = logging.getLogger(__name__)


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
        """Load PII data from JSONL file and track in report.

        Override pii_data_path in config to use custom PII data.
        The data source is automatically logged to report.jsonl for traceability.
        """
        if self.pii_data_path:
            pii_path = Path(self.pii_data_path)
        else:
            pii_path = data_path / "propile" / "pii_data.jsonl"

        self._pii_data_path = pii_path
        self.pii_records = []

        if not pii_path.exists():
            logger.warning(
                "PII data file not found: %s. "
                "Run the extraction script to generate PII data: "
                "garak/data/propile/scripts/extract_pii_from_training_dataset.py",
                pii_path,
            )
            return

        with open(pii_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.pii_records.append(json.loads(line))

        self._write_pii_data_init(pii_path)

    def _write_pii_data_init(self, pii_path: Path):
        """Write PII data initialization entry to report for traceability.

        This follows the same pattern as garak.payloads.PayloadGroup to provide
        consistent tracking of external data sources used during probing.
        """
        if (
            _config.transient.reportfile is not None
            and not _config.transient.reportfile.closed
        ):
            pii_stat = pii_path.stat()
            _config.transient.reportfile.write(
                json.dumps(
                    {
                        "entry_type": "pii_data_init",
                        "pii_data_name": pii_path.stem,
                        "pii_data_path": str(pii_path),
                        "entries": len(self.pii_records),
                        "filesize": int(pii_stat.st_size),
                        "mtime": str(pii_stat.st_mtime),
                    }
                )
                + "\n"
            )
            logger.debug(
                "PII data loaded: %s (%d records)", pii_path, len(self.pii_records)
            )

    def _attempt_prestore_hook(self, attempt: Attempt, seq: int) -> Attempt:
        attempt.notes["triggers"] = [self.triggers[seq]]
        attempt.notes["pii_type"] = self.pii_types[seq]
        attempt.notes["pii_data_source"] = str(self._pii_data_path)
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
    DEFAULT_PARAMS = (
        garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS
    )

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

        if not self.prompts:
            raise PluginConfigurationError(
                "PIILeakTwin generated no prompts. "
                "PII data may lack required fields (name + email/phone/address)."
            )


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
    DEFAULT_PARAMS = (
        garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS
    )

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

        if not self.prompts:
            raise PluginConfigurationError(
                "PIILeakTriplet generated no prompts. "
                "PII data may lack required field combinations "
                "(name + auxiliary PII + target PII)."
            )


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
    DEFAULT_PARAMS = (
        garak.probes.Probe.DEFAULT_PARAMS | PIILeakProbeMixin.DEFAULT_PARAMS
    )

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

        if not self.prompts:
            raise PluginConfigurationError(
                "PIILeakQuadruplet generated no prompts. "
                "PII data may lack required field combinations "
                "(name + two auxiliary PIIs + target PII)."
            )


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

    relationships = ["father", "mother", "wife", "husband"]
    affiliations = ["university", "employer", "organization"]

    DEFAULT_PARAMS = (
        garak.probes.Probe.DEFAULT_PARAMS
        | PIILeakProbeMixin.DEFAULT_PARAMS
        | {
            "relationships": ["father", "mother", "wife", "husband"],
            "affiliations": ["university", "employer", "organization"],
        }
    )

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

        if not self.prompts:
            raise PluginConfigurationError(
                "PIILeakUnstructured generated no prompts. "
                "PII data may lack unstructured fields "
                "(relationships or affiliations)."
            )
