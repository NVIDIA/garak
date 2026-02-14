#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Extract PII from open training datasets for ProPILE probes.

This script extracts personally identifiable information (PII) from large open
training datasets like NVIDIA's Nemotron-CC [1], which are commonly used for
LLM pretraining. The extracted PII can then be used with garak's ProPILE probes
to test whether models have memorized training data.

We focus on PII from known training corpora because it gives us confirmed
instances of data that models may have seen during training. This approach is
also safer from a sourcing perspective since we are not originating the exposure,
just testing for memorization that may have already occurred.

The script uses HuggingFace's datasets library [2] to stream data from the Hub,
which allows processing large datasets without downloading them entirely. For
PII detection, we use Microsoft's Presidio [3], an open source framework that
combines pattern matching with Named Entity Recognition. Presidio relies on
spaCy [4] for the NER backend, specifically the en_core_web_lg model which
provides good accuracy for detecting person names and organizations.

Background
----------
The original ProPILE paper [5] used the Enron email dataset [6], which is part
of The Pile training corpus. Enron emails naturally contain rich PII because
business email signatures often include name, email, phone, and address together.
This makes Enron well suited for triplet and quadruplet probes, which need
records with multiple PII fields.

Web crawl datasets like Nemotron-CC tend to have sparser PII since contact pages
usually list either email or phone, rarely both for the same person. The bundled
pii_data.jsonl from Nemotron-CC works well for twin probes (name plus one PII
field) but has limited data for triplet and quadruplet probes. If you need
richer PII records, consider using the Enron dataset as shown below.

Requirements
------------
First, install the extraction dependencies and download the spaCy model::

    cd garak/data/propile/scripts
    pip install -r requirements.txt
    python -m spacy download en_core_web_lg

Then authenticate with HuggingFace since some datasets like Nemotron-CC require
accepting a license agreement::

    hf auth login

You can also set the HF_TOKEN environment variable instead. For gated datasets,
visit the dataset page on HuggingFace Hub and accept the license before running
the script.

Usage
-----
Basic usage with Nemotron-CC::

    python extract_pii_from_training_dataset.py --subset High-Quality

With custom parameters::

    python extract_pii_from_training_dataset.py \\
        --dataset nvidia/Nemotron-CC-v2.1 \\
        --subset High-Quality \\
        --max-samples 10000 \\
        --max-records 500 \\
        --output ../pii_data.jsonl

Using the Enron dataset for richer PII (better for triplet/quadruplet probes)::

    python extract_pii_from_training_dataset.py \\
        --dataset LLM-PBE/enron-email \\
        --max-samples 10000 \\
        --output ../enron_pii.jsonl

Safety Filtering
----------------
By default, this script filters out highly sensitive PII types like Social
Security Numbers, credit card numbers, bank account numbers, medical record
numbers, and passwords or API keys. These are too sensitive to redistribute
and are not needed for typical memorization testing.

The script keeps relatively safer PII types that are useful for testing: names,
email addresses, phone numbers, and organizations. If you need to include
sensitive PII types for specific research purposes, use the --include-sensitive
flag, but do not redistribute datasets containing SSNs, credit cards, or
similar data.

References
----------
[1] NVIDIA Nemotron-CC: https://huggingface.co/datasets/nvidia/Nemotron-CC-v2.1
[2] HuggingFace datasets: https://huggingface.co/docs/datasets
[3] Microsoft Presidio: https://microsoft.github.io/presidio/
[4] spaCy NLP: https://spacy.io/
[5] ProPILE paper: https://arxiv.org/abs/2307.01881
[6] Enron email dataset: https://huggingface.co/datasets/LLM-PBE/enron-email
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# PII types to extract (relatively safe for redistribution)
ALLOWED_PII_TYPES = {
    "PERSON",           # Names
    "EMAIL_ADDRESS",    # Email addresses
    "PHONE_NUMBER",     # Phone numbers
    "ORGANIZATION",     # Company/org names (for context)
}

# Common words/patterns that are falsely detected as person names
FALSE_NAME_PATTERNS = {
    # Articles and pronouns
    "the", "a", "an", "this", "that", "it", "i", "you", "we", "they",
    # Titles
    "mr", "mrs", "ms", "dr", "prof", "sir", "lord", "lady",
    # Months
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    # Days
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    # Seasons and holidays
    "spring", "summer", "fall", "winter", "autumn",
    "easter", "christmas", "diwali", "hanukkah", "ramadan",
    # Common tech/UI terms
    "dashboard", "admin", "user", "login", "logout", "settings", "menu",
    "home", "contact", "about", "services", "products", "blog",
    # Common nouns often misdetected
    "cybercriminals", "hackers", "users", "customers", "clients",
    "members", "visitors", "guests", "patients", "students",
}

# PII types to filter out (too sensitive to redistribute)
EXCLUDED_PII_TYPES = {
    "US_SSN",           # Social Security Numbers
    "CREDIT_CARD",      # Credit card numbers
    "CRYPTO",           # Cryptocurrency addresses
    "US_BANK_NUMBER",   # Bank account numbers
    "IBAN_CODE",        # International bank accounts
    "US_PASSPORT",      # Passport numbers
    "US_DRIVER_LICENSE",# Driver's license
    "MEDICAL_LICENSE",  # Medical IDs
    "IP_ADDRESS",       # IP addresses (privacy concern)
    "PASSWORD",         # Passwords
    "AWS_ACCESS_KEY",   # API keys
    "AZURE_AUTH_TOKEN", # Auth tokens
}


@dataclass
class PIIRecord:
    """A single PII record extracted from training data."""
    name: str = ""
    email: str = ""
    phone: str = ""
    organization: str = ""
    source_dataset: str = ""
    source_id: str = ""

    def is_valid(self) -> bool:
        """Check if record has minimum required fields.

        Requires a name plus at least one contact method (email or phone).
        This stricter validation produces higher quality records.
        """
        return bool(self.name) and bool(self.email or self.phone)

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding empty fields."""
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class ExtractionStats:
    """Statistics about the extraction process."""
    samples_processed: int = 0
    records_extracted: int = 0
    entities_by_type: dict = field(default_factory=lambda: defaultdict(int))
    excluded_entities: dict = field(default_factory=lambda: defaultdict(int))


def check_dependencies() -> bool:
    """Check if required dependencies are installed."""
    missing = []

    try:
        import presidio_analyzer
    except ImportError:
        missing.append("presidio-analyzer")

    try:
        import spacy
        try:
            spacy.load("en_core_web_lg")
        except OSError:
            missing.append("spacy model 'en_core_web_lg' (run: python -m spacy download en_core_web_lg)")
    except ImportError:
        missing.append("spacy")

    try:
        from datasets import load_dataset
    except ImportError:
        missing.append("datasets")

    if missing:
        logger.error("Missing dependencies: %s", ", ".join(missing))
        logger.error("Install with: pip install presidio-analyzer spacy datasets")
        logger.error("Then run: python -m spacy download en_core_web_lg")
        return False

    return True


def create_analyzer():
    """Create and configure the Presidio analyzer."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
    })
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    return analyzer


def is_valid_name(value: str) -> bool:
    """Check if a detected PERSON entity looks like a real person name.

    Filters out common false positives like single words, dates, seasons,
    and obviously non-name patterns.
    """
    # Must have at least 2 characters
    if len(value) < 3:
        return False

    # Should not be all uppercase (often organizations or acronyms)
    if value.isupper() and len(value) > 3:
        return False

    # Check against known false positives
    lower_value = value.lower().strip()
    if lower_value in FALSE_NAME_PATTERNS:
        return False

    # Names starting with "the" are usually not person names
    if lower_value.startswith("the "):
        return False

    # Names with newlines or excessive punctuation are garbage
    if "\n" in value or value.count(".") > 2:
        return False

    # Single word names are often false positives, prefer full names
    words = value.split()
    if len(words) == 1:
        # Single word names must be capitalized and reasonably long
        if not value[0].isupper() or len(value) < 4:
            return False

    return True


def is_valid_organization(value: str) -> bool:
    """Check if a detected ORGANIZATION entity is valid."""
    if len(value) < 3 or len(value) > 100:
        return False
    if "\n" in value or "\t" in value:
        return False
    if len(value.split()) == 1 and len(value) < 4:
        return False
    return True


def is_valid_phone(value: str) -> bool:
    """Check if a detected phone number looks legitimate."""
    digits = re.sub(r'[^\d]', '', value)

    # Must have 7-15 digits (international range)
    if len(digits) < 7 or len(digits) > 15:
        return False

    # Reject if it looks like a year (4 digits starting with 1 or 2)
    if len(digits) == 4 and digits[0] in '12':
        return False

    # Reject floating point numbers (coordinates, etc.)
    if '.' in value and re.search(r'\d+\.\d+', value):
        return False

    # Reject fractions
    if '/' in value:
        return False

    return True


# Minimum confidence scores by entity type
MIN_CONFIDENCE = {
    "PERSON": 0.85,
    "EMAIL_ADDRESS": 0.8,
    "PHONE_NUMBER": 0.75,
    "ORGANIZATION": 0.85,
}


def extract_pii_from_text(
    analyzer,
    text: str,
    stats: ExtractionStats,
    include_sensitive: bool = False
) -> dict[str, list[str]]:
    """Extract PII entities from a text sample.

    Args:
        analyzer: Presidio AnalyzerEngine instance
        text: Text to analyze
        stats: Statistics tracker
        include_sensitive: If True, include sensitive PII types (SSN, credit cards, etc.)

    Returns:
        Dictionary mapping PII types to list of extracted values
    """
    if not text or len(text) < 50:
        return {}

    text = text[:50000]

    active_types = ALLOWED_PII_TYPES | EXCLUDED_PII_TYPES if include_sensitive else ALLOWED_PII_TYPES

    try:
        results = analyzer.analyze(
            text=text,
            language="en",
            entities=list(ALLOWED_PII_TYPES | EXCLUDED_PII_TYPES),
            score_threshold=0.7,
        )
    except Exception as e:
        logger.debug("Analysis error: %s", e)
        return {}

    extracted = defaultdict(list)

    for result in results:
        entity_type = result.entity_type
        value = text[result.start:result.end].strip()

        if entity_type in EXCLUDED_PII_TYPES and not include_sensitive:
            stats.excluded_entities[entity_type] += 1
            continue

        if entity_type not in active_types:
            continue

        min_score = MIN_CONFIDENCE.get(entity_type, 0.7)
        if result.score < min_score:
            continue

        if len(value) < 2 or len(value) > 200:
            continue

        if entity_type == "PERSON" and not is_valid_name(value):
            continue
        if entity_type == "ORGANIZATION" and not is_valid_organization(value):
            continue
        if entity_type == "PHONE_NUMBER" and not is_valid_phone(value):
            continue

        extracted[entity_type].append(value)
        stats.entities_by_type[entity_type] += 1

    return extracted


def correlate_pii_entities(extracted: dict[str, list[str]]) -> list[PIIRecord]:
    """Correlate PII entities into coherent records.

    Creates records combining all available PII for a person when possible.
    This enables triplet probes (which need name + email + phone).
    """
    records = []

    names = extracted.get("PERSON", [])
    emails = extracted.get("EMAIL_ADDRESS", [])
    phones = extracted.get("PHONE_NUMBER", [])

    if not names:
        return records

    primary_name = names[0]
    primary_email = emails[0] if emails else ""
    primary_phone = phones[0] if phones else ""

    if primary_email and primary_phone:
        record = PIIRecord(name=primary_name, email=primary_email, phone=primary_phone)
        if record.is_valid():
            records.append(record)
    elif primary_email:
        record = PIIRecord(name=primary_name, email=primary_email)
        if record.is_valid():
            records.append(record)
    elif primary_phone:
        record = PIIRecord(name=primary_name, phone=primary_phone)
        if record.is_valid():
            records.append(record)

    return records[:3]


def load_dataset_stream(
    dataset_name: str,
    subset: Optional[str] = None,
    split: str = "train"
) -> Iterator[dict]:
    """Load a HuggingFace dataset in streaming mode.

    Args:
        dataset_name: HuggingFace dataset identifier
        subset: Optional dataset subset/configuration
        split: Dataset split to use

    Yields:
        Dataset samples as dictionaries
    """
    from datasets import load_dataset

    logger.info("Loading dataset: %s (subset=%s, split=%s)", dataset_name, subset, split)

    try:
        if subset:
            ds = load_dataset(dataset_name, subset, split=split, streaming=True)
        else:
            ds = load_dataset(dataset_name, split=split, streaming=True)

        for sample in ds:
            yield sample

    except Exception as e:
        logger.error("Failed to load dataset: %s", e)
        raise


def extract_text_from_sample(sample: dict) -> str:
    """Extract text content from a dataset sample.

    Handles different dataset schemas:
    - Nemotron-CC: 'text' field
    - Common patterns: 'content', 'text', 'document'
    """
    # Try common field names
    for field_name in ["text", "content", "document", "passage"]:
        if field_name in sample and isinstance(sample[field_name], str):
            return sample[field_name]

    # If sample is a string itself
    if isinstance(sample, str):
        return sample

    return ""


def extract_pii_from_dataset(
    dataset_name: str,
    max_samples: int = 10000,
    max_records: int = 500,
    subset: Optional[str] = None,
    output_path: Optional[Path] = None,
    include_sensitive: bool = False
) -> list[PIIRecord]:
    """Extract PII records from a HuggingFace dataset.

    Args:
        dataset_name: HuggingFace dataset identifier
        max_samples: Maximum number of samples to process
        max_records: Maximum number of PII records to extract
        subset: Optional dataset subset
        output_path: Path to write output JSONL
        include_sensitive: If True, include sensitive PII types (SSN, credit cards, etc.)

    Returns:
        List of extracted PIIRecord objects
    """
    logger.info("Starting PII extraction from %s", dataset_name)
    logger.info("Max samples: %d, Max records: %d", max_samples, max_records)
    if include_sensitive:
        logger.warning(
            "Sensitive PII extraction enabled. Output may contain SSNs, credit cards, "
            "and other sensitive data. Do not redistribute without careful review."
        )

    analyzer = create_analyzer()
    stats = ExtractionStats()
    all_records = []
    seen_names = set()

    try:
        dataset_iter = load_dataset_stream(dataset_name, subset=subset)

        for sample in dataset_iter:
            if stats.samples_processed >= max_samples:
                break
            if len(all_records) >= max_records:
                break

            stats.samples_processed += 1

            if stats.samples_processed % 100 == 0:
                logger.info(
                    "Progress: %d samples, %d records extracted",
                    stats.samples_processed, len(all_records)
                )

            text = extract_text_from_sample(sample)
            if not text:
                continue

            extracted = extract_pii_from_text(analyzer, text, stats, include_sensitive)
            if not extracted:
                continue

            records = correlate_pii_entities(extracted)

            for record in records:
                # Deduplicate by name
                if record.name.lower() in seen_names:
                    continue
                seen_names.add(record.name.lower())

                record.source_dataset = dataset_name
                record.source_id = sample.get("uuid", sample.get("id", ""))

                all_records.append(record)
                stats.records_extracted += 1

                if len(all_records) >= max_records:
                    break

    except KeyboardInterrupt:
        logger.info("Extraction interrupted by user")

    # Log statistics
    logger.info("=" * 50)
    logger.info("Extraction complete!")
    logger.info("Samples processed: %d", stats.samples_processed)
    logger.info("Records extracted: %d", stats.records_extracted)
    logger.info("Entities by type:")
    for etype, count in sorted(stats.entities_by_type.items()):
        logger.info("  %s: %d", etype, count)
    if stats.excluded_entities:
        logger.info("Excluded sensitive entities:")
        for etype, count in sorted(stats.excluded_entities.items()):
            logger.info("  %s: %d (excluded for safety)", etype, count)

    # Write output
    if output_path and all_records:
        logger.info("Writing %d records to %s", len(all_records), output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            for record in all_records:
                f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    return all_records


def main():
    parser = argparse.ArgumentParser(
        description="Extract PII from open training datasets for ProPILE probes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--dataset",
        default="nvidia/Nemotron-CC-v2.1",
        help="HuggingFace dataset to extract from (default: nvidia/Nemotron-CC-v2.1)"
    )
    parser.add_argument(
        "--subset",
        default=None,
        help="Dataset subset/configuration to use"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=10000,
        help="Maximum samples to process (default: 10000)"
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=500,
        help="Maximum PII records to extract (default: 500)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path(__file__).parent.parent / "nemotron_pii.jsonl",
        help="Output JSONL file path"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help=(
            "Include sensitive PII types (SSN, credit cards, bank accounts, etc.). "
            "Do not redistribute datasets containing this data."
        )
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not check_dependencies():
        sys.exit(1)

    records = extract_pii_from_dataset(
        dataset_name=args.dataset,
        max_samples=args.max_samples,
        max_records=args.max_records,
        subset=args.subset,
        output_path=args.output,
        include_sensitive=args.include_sensitive
    )

    if records:
        logger.info("Successfully extracted %d PII records", len(records))
        logger.info("Output written to: %s", args.output)
    else:
        logger.warning("No PII records extracted")
        sys.exit(1)


if __name__ == "__main__":
    main()
