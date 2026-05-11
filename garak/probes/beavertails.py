"""**BeaverTails: a human preference dataset for safety alignment

Probes that test model safety using the BeaverTails dataset - a collection of
prompts developed to evaluate safety alignment in large language models.

The dataset includes 27,186 question-answer pairs annotated across 14 harm categories.
Only unsafe prompts are included in these probes.

Further info:
* https://arxiv.org/abs/2307.04657
* https://sites.google.com/view/pku-beavertails
"""

import logging
from pathlib import Path

from garak import _config
from garak.data import path as data_path
import garak.probes


class BeaverTailsBase(garak.probes.Probe):
    """Base probe for BeaverTails safety evaluation

    Loads unsafe prompts from the BeaverTails dataset and tests model safety.
    Supports loading from local cached files or from HuggingFace dataset.
    """

    lang = "en"
    goal = "test model safety alignment using real-world harmful prompts"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = False
    doc_uri = "https://arxiv.org/abs/2307.04657"
    tags = [
        "avid-effect:security:S0301",
        "owasp:llm01",
        "owasp:llm02",
        "quality:Security:PromptStability",
        "payload:jailbreak",
    ]
    primary_detector = "mitigation.MitigationBypass"

    # Override in subclasses - filename of the data file (without .txt extension)
    data_file = None
    # Override in subclasses - HuggingFace category filter key
    hf_category_key = None

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.prompts = []
        self._load_beavertails_data()

    def _load_beavertails_data(self):
        """Load BeaverTails prompts from local files or HuggingFace dataset"""
        if not self.data_file:
            logging.warning("No data_file specified for %s", self.__class__.__name__)
            self.prompts = []
            return

        # Try loading from local cache first
        if self._try_load_from_local():
            logging.debug("Loaded %d prompts from local cache", len(self.prompts))
        else:
            # Fall back to HuggingFace if available
            self._load_from_huggingface()

        # Cap the number of prompts if configured
        if self.soft_probe_prompt_cap:
            self._prune_data(self.soft_probe_prompt_cap)

    def _try_load_from_local(self) -> bool:
        """Try loading from local cached files. Returns True if successful."""
        try:
            data_file_path = data_path / "beavertails" / f"{self.data_file}.txt"
            if not data_file_path.exists():
                return False

            with open(data_file_path, "r", encoding="utf-8") as f:
                self.prompts = [line.strip() for line in f if line.strip()]
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.debug("Failed to load from local cache: %s", e)
            return False

    def _load_from_huggingface(self):
        """Load BeaverTails prompts from HuggingFace dataset"""
        try:
            from datasets import load_dataset
        except ImportError:
            logging.error(
                "BeaverTails dataset not found locally and 'datasets' library "
                "not available. Install it with: pip install datasets"
            )
            self.prompts = []
            return

        try:
            logging.debug("Loading BeaverTails from HuggingFace...")
            dataset = load_dataset(
                "PKU-Alignment/BeaverTails",
                split="30k_train",
                trust_remote_code=True,
            )

            # Filter for unsafe prompts in this category
            self.prompts = []
            if self.hf_category_key:
                for item in dataset:
                    if not item["is_safe"] and item["category"].get(
                        self.hf_category_key
                    ):
                        self.prompts.append(item["prompt"])
            else:
                # For "all" probes, get all unsafe prompts
                for item in dataset:
                    if not item["is_safe"]:
                        self.prompts.append(item["prompt"])

            logging.debug(
                "Loaded %d prompts from HuggingFace for %s",
                len(self.prompts),
                self.hf_category_key or "all categories",
            )
        except Exception as e:  # pylint: disable=broad-except
            logging.error("Failed to load BeaverTails from HuggingFace: %s", e)
            self.prompts = []


class BeaverTailsAll(BeaverTailsBase):
    """BeaverTails probe combining unsafe prompts from all harm categories.

    Tests model safety using all 25,357 unsafe prompts from the BeaverTails
    dataset across 14 harm categories.
    """

    active = True
    data_file = "beavertails_all"
    hf_category_key = None

    def __init__(self, config_root=_config):
        garak.probes.Probe.__init__(self, config_root=config_root)
        self.prompts = []
        self._load_beavertails_data()

    def _try_load_from_local(self) -> bool:
        """Try loading from local cached files. Returns True if successful."""
        category_files = [
            "beavertails_animal_abuse",
            "beavertails_child_abuse",
            "beavertails_controversial_topics_politics",
            "beavertails_discrimination_stereotype_injustice",
            "beavertails_drug_abuse_weapons_banned_substance",
            "beavertails_financial_crime_property_crime_theft",
            "beavertails_hate_speech_offensive_language",
            "beavertails_misinformation_regarding_ethics_laws_and_safety",
            "beavertails_non_violent_unethical_behavior",
            "beavertails_privacy_violation",
            "beavertails_self_harm",
            "beavertails_sexually_explicit_adult_content",
            "beavertails_terrorism_organized_crime",
            "beavertails_violence_aiding_and_abetting_incitement",
        ]
        all_prompts = []
        files_found = 0

        for category_file in category_files:
            try:
                data_file_path = data_path / "beavertails" / f"{category_file}.txt"
                if not data_file_path.exists():
                    continue

                with open(data_file_path, "r", encoding="utf-8") as f:
                    all_prompts.extend([line.strip() for line in f if line.strip()])
                files_found += 1
            except Exception as e:  # pylint: disable=broad-except
                logging.debug("Failed to load %s: %s", category_file, e)

        if files_found == len(category_files):
            self.prompts = all_prompts
            return True
        return False


class BeaverTailsAnimalAbuse(BeaverTailsBase):
    """BeaverTails probe: Animal Abuse category.

    Tests model safety using prompts related to animal abuse (357 unsafe examples).
    """

    data_file = "beavertails_animal_abuse"
    hf_category_key = "animal_abuse"


class BeaverTailsChildAbuse(BeaverTailsBase):
    """BeaverTails probe: Child Abuse category.

    Tests model safety using prompts related to child abuse (185 unsafe examples).
    """

    data_file = "beavertails_child_abuse"
    hf_category_key = "child_abuse"


class BeaverTailsControversialTopics(BeaverTailsBase):
    """BeaverTails probe: Controversial Topics/Politics category.

    Tests model safety using prompts related to controversial topics and politics
    (907 unsafe examples).
    """

    data_file = "beavertails_controversial_topics_politics"
    hf_category_key = "controversial_topics,politics"


class BeaverTailsDiscrimination(BeaverTailsBase):
    """BeaverTails probe: Discrimination/Stereotype/Injustice category.

    Tests model safety using prompts related to discrimination, stereotypes, and
    injustice (2,352 unsafe examples).
    """

    data_file = "beavertails_discrimination_stereotype_injustice"
    hf_category_key = "discrimination,stereotype,injustice"


class BeaverTailsDrugAbuse(BeaverTailsBase):
    """BeaverTails probe: Drug Abuse/Weapons/Banned Substances category.

    Tests model safety using prompts related to drug abuse, weapons, and banned
    substances (1,527 unsafe examples).
    """

    data_file = "beavertails_drug_abuse_weapons_banned_substance"
    hf_category_key = "drug_abuse,weapons,banned_substance"


class BeaverTailsFinancialCrime(BeaverTailsBase):
    """BeaverTails probe: Financial Crime/Property Crime/Theft category.

    Tests model safety using prompts related to financial crime, property crime,
    and theft (2,566 unsafe examples).
    """

    data_file = "beavertails_financial_crime_property_crime_theft"
    hf_category_key = "financial_crime,property_crime,theft"


class BeaverTailsHateSpeech(BeaverTailsBase):
    """BeaverTails probe: Hate Speech/Offensive Language category.

    Tests model safety using prompts related to hate speech and offensive language
    (2,560 unsafe examples).
    """

    data_file = "beavertails_hate_speech_offensive_language"
    hf_category_key = "hate_speech,offensive_language"


class BeaverTailsMisinformation(BeaverTailsBase):
    """BeaverTails probe: Misinformation/Ethics/Laws/Safety category.

    Tests model safety using prompts related to misinformation regarding ethics,
    laws, and safety (652 unsafe examples).
    """

    data_file = "beavertails_misinformation_regarding_ethics_laws_and_safety"
    hf_category_key = "misinformation_regarding_ethics,laws_and_safety"


class BeaverTailsUnethicalBehavior(BeaverTailsBase):
    """BeaverTails probe: Non-Violent Unethical Behavior category.

    Tests model safety using prompts related to non-violent unethical behavior
    (4,821 unsafe examples).
    """

    data_file = "beavertails_non_violent_unethical_behavior"
    hf_category_key = "non_violent_unethical_behavior"


class BeaverTailsPrivacyViolation(BeaverTailsBase):
    """BeaverTails probe: Privacy Violation category.

    Tests model safety using prompts related to privacy violations
    (1,400 unsafe examples).
    """

    data_file = "beavertails_privacy_violation"
    hf_category_key = "privacy_violation"


class BeaverTailsSelfHarm(BeaverTailsBase):
    """BeaverTails probe: Self Harm category.

    Tests model safety using prompts related to self harm (205 unsafe examples).
    """

    data_file = "beavertails_self_harm"
    hf_category_key = "self_harm"


class BeaverTailsSexualContent(BeaverTailsBase):
    """BeaverTails probe: Sexually Explicit/Adult Content category.

    Tests model safety using prompts related to sexually explicit and adult content
    (704 unsafe examples).
    """

    data_file = "beavertails_sexually_explicit_adult_content"
    hf_category_key = "sexually_explicit,adult_content"


class BeaverTailsTerrorism(BeaverTailsBase):
    """BeaverTails probe: Terrorism/Organized Crime category.

    Tests model safety using prompts related to terrorism and organized crime
    (294 unsafe examples).
    """

    data_file = "beavertails_terrorism_organized_crime"
    hf_category_key = "terrorism,organized_crime"


class BeaverTailsViolence(BeaverTailsBase):
    """BeaverTails probe: Violence/Aiding/Incitement category.

    Tests model safety using prompts related to violence, aiding and abetting, and
    incitement (6,927 unsafe examples).
    """

    data_file = "beavertails_violence_aiding_and_abetting_incitement"
    hf_category_key = "violence,aiding_and_abetting,incitement"
