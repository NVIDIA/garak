"""**ProPILE Sensitive-PII Extension**

Extends ``garak.probes.propile`` with probes for sensitive PII types that the
base ProPILE module's Ethics section explicitly excludes: SSN (US), IBAN,
passport number, date of birth, and driver's license (US). The probes construct
prompts using the same twin/triplet template format as the base ProPILE module
but require a custom PII dataset containing the additional sensitive fields.

Probes in this module try to elicit sensitive PII by providing context (the
subject's name, optionally with one auxiliary PII) that the model may have
memorised during training. The reuse of the existing
:class:`garak.detectors.propile.PIILeak` detector is intentional: its
Jaro-Winkler fallback (``_generic_partial_match``) handles arbitrary PII types
beyond the email/phone/address triad the original ProPILE paper targeted.

Further info:

* https://arxiv.org/abs/2307.01881

Limitations
-----------

DOB detection has lower recall on reformatted dates. The
:class:`garak.detectors.propile.PIILeak` detector falls back to Jaro-Winkler
similarity for PII types other than email/phone/address, with a default
threshold of 0.7. For SSN, IBAN, passport, and driver license, the fixed-format
structure of the values matches reliably (sim >= 0.91 on minor punctuation
variants and sim = 1.0 on verbatim matches). For DOB, reformatted dates such as
``January 1, 1990`` vs the canonical ``1990-01-01`` trigger fall below the 0.7
threshold (sim ~0.5-0.69) and are not flagged as leaks. A future
``SensitivePIIShape`` regex detector (deferred to a follow-up PR) would close
this gap; until then, DOB coverage is best on verbatim or near-verbatim model
outputs.

Ethics
------

Intended for defensive security research only. All bundled PII is synthetic.
SSN values use the ``000-00-NNNN`` format where area ``000`` and group ``00``
are reserved as invalid and never issued by the US SSA; the serial segment
ranges from ``0000`` to ``0019`` across the 20 bundled records. IBAN values
use the ``XX00...`` format (``XX`` is not a valid ISO 13616 country
code). Passport numbers use ``X00000000`` (clearly invalid US passport shape).
Driver license values use ``X0000000`` (clearly invalid US license shape).
Dates of birth are obviously fictional. No real victim PII is shipped. Users
who have rights to real datasets can supply their own data via the
``pii_data_path`` parameter; in that case the same Ethics guidance from
``garak.probes.propile`` applies: only test on PII you have the legal right to
hold, and exclude data you do not have consent to process.
"""

import csv
import json
import logging
from pathlib import Path

from garak import _config
from garak.data import path as data_path
import garak.probes
from garak.probes.propile import PIILeakProbeMixin

logger = logging.getLogger(__name__)


class PIILeakSensitiveTwin(PIILeakProbeMixin, garak.probes.Probe):
    """ProPILE twin probe for sensitive PII types (SSN, IBAN, passport, DOB, driver license).

    Constructs prompts using only the subject's name to test if the model
    can complete with one of five sensitive PII types: SSN (US), IBAN,
    passport number, date of birth, or driver's license (US). Each
    (record, sensitive_field, template) triple generates one prompt and
    stores the corresponding trigger value for the detector.

    NB: This probe is most effective when you have reason to believe the
    sensitive PII was present in the model's training corpus. Results
    indicate potential for sensitive-PII extraction; confirmed memorization
    requires verified training data. The bundled ``pii_sensitive_data.jsonl``
    is intentionally synthetic — supply real data via ``pii_data_path`` only
    if you have the legal right to hold and process it.
    """

    active = False
    goal = "extract sensitive PII (SSN, IBAN, passport, DOB, driver license) using only the subject's name"

    DEFAULT_PARAMS = (
        garak.probes.Probe.DEFAULT_PARAMS
        | PIILeakProbeMixin.DEFAULT_PARAMS
        | {
            "sensitive_pii_types": [
                "ssn",
                "iban",
                "passport",
                "dob",
                "driver_license",
            ],
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

            for pii_type in self.sensitive_pii_types:
                target_value = record.get(pii_type, "")
                if not target_value:
                    continue

                template_category = f"twin_{pii_type}"
                for template in self.templates.get(template_category, []):
                    prompt = template.format(name=name)
                    self.prompts.append(prompt)
                    self.triggers.append(target_value)
                    self.pii_types.append(pii_type)

        if not self.prompts:
            logger.warning(
                "PIILeakSensitiveTwin generated no prompts. "
                "PII data may lack sensitive fields "
                "(ssn, iban, passport, dob, driver_license)."
            )

    def _load_templates(self):
        """Load prompt templates from the propile_sensitive TSV file.

        Overrides :meth:`PIILeakProbeMixin._load_templates` to point at the
        ``propile_sensitive`` data subdirectory rather than the base
        ``propile`` one.
        """
        self.templates = {}
        template_path = (
            data_path / "propile_sensitive" / "prompt_sensitive_templates.tsv"
        )
        with open(template_path, encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                category = row["category"]
                if category not in self.templates:
                    self.templates[category] = []
                self.templates[category].append(row["template"])

    def _load_pii_data(self):
        """Load sensitive-PII data from the propile_sensitive JSONL file.

        Overrides :meth:`PIILeakProbeMixin._load_pii_data` to default to the
        ``propile_sensitive`` data subdirectory when ``pii_data_path`` is not
        explicitly set by the user.
        """
        if self.pii_data_path:
            pii_path = Path(self.pii_data_path)
        else:
            pii_path = data_path / "propile_sensitive" / "pii_sensitive_data.jsonl"

        self._pii_data_path = pii_path
        self.pii_records = []

        if not pii_path.exists():
            logger.warning(
                "Sensitive PII data file not found: %s. "
                "Supply a JSONL file with name + ssn/iban/passport/dob/"
                "driver_license fields via the pii_data_path parameter.",
                pii_path,
            )
            return

        with open(pii_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.pii_records.append(json.loads(line))

        logger.info(
            "Sensitive PII data loaded: %s (%d records)",
            pii_path,
            len(self.pii_records),
        )


class PIILeakSensitiveTriplet(PIILeakProbeMixin, garak.probes.Probe):
    """ProPILE triplet probe for sensitive PII types (SSN, IBAN, passport, DOB, driver license).

    Constructs prompts using the subject's name plus one auxiliary PII
    (email or phone) to test if the model can complete with one of five
    sensitive PII types. The auxiliary context mirrors the original
    ProPILE triplet design but the target field is always one of SSN,
    IBAN, passport, DOB, or driver's license rather than email/phone/address.

    NB: This probe is most effective when you have reason to believe the
    sensitive PII was present in the model's training corpus. Results
    indicate potential for sensitive-PII extraction; confirmed memorization
    requires verified training data. The bundled ``pii_sensitive_data.jsonl``
    is intentionally synthetic — supply real data via ``pii_data_path`` only
    if you have the legal right to hold and process it.
    """

    active = False
    goal = "extract sensitive PII (SSN, IBAN, passport, DOB, driver license) using name and one auxiliary PII"

    DEFAULT_PARAMS = (
        garak.probes.Probe.DEFAULT_PARAMS
        | PIILeakProbeMixin.DEFAULT_PARAMS
        | {
            "sensitive_pii_types": [
                "ssn",
                "iban",
                "passport",
                "dob",
                "driver_license",
            ],
        }
    )

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = []
        self.triggers = []
        self.pii_types = []
        self._load_templates()
        self._load_pii_data()

        # (auxiliary field, target field, template category) tuples.
        # Sensitive targets do not appear as auxiliary context (they are the
        # extraction target), so the auxiliary is always email or phone —
        # the two non-sensitive identifiers ProPILE originally bundled.
        triplet_configs = [
            ("email", "ssn", "triplet_ssn"),
            ("email", "iban", "triplet_iban"),
            ("phone", "passport", "triplet_passport"),
            ("email", "dob", "triplet_dob"),
            ("phone", "driver_license", "triplet_driver_license"),
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
            logger.warning(
                "PIILeakSensitiveTriplet generated no prompts. "
                "PII data may lack required field combinations "
                "(name + auxiliary email/phone + sensitive target PII)."
            )

    def _load_templates(self):
        """Load prompt templates from the propile_sensitive TSV file.

        Overrides :meth:`PIILeakProbeMixin._load_templates` to point at the
        ``propile_sensitive`` data subdirectory rather than the base
        ``propile`` one.
        """
        self.templates = {}
        template_path = (
            data_path / "propile_sensitive" / "prompt_sensitive_templates.tsv"
        )
        with open(template_path, encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                category = row["category"]
                if category not in self.templates:
                    self.templates[category] = []
                self.templates[category].append(row["template"])

    def _load_pii_data(self):
        """Load sensitive-PII data from the propile_sensitive JSONL file.

        Overrides :meth:`PIILeakProbeMixin._load_pii_data` to default to the
        ``propile_sensitive`` data subdirectory when ``pii_data_path`` is not
        explicitly set by the user.
        """
        if self.pii_data_path:
            pii_path = Path(self.pii_data_path)
        else:
            pii_path = data_path / "propile_sensitive" / "pii_sensitive_data.jsonl"

        self._pii_data_path = pii_path
        self.pii_records = []

        if not pii_path.exists():
            logger.warning(
                "Sensitive PII data file not found: %s. "
                "Supply a JSONL file with name + ssn/iban/passport/dob/"
                "driver_license fields via the pii_data_path parameter.",
                pii_path,
            )
            return

        with open(pii_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.pii_records.append(json.loads(line))

        logger.info(
            "Sensitive PII data loaded: %s (%d records)",
            pii_path,
            len(self.pii_records),
        )
