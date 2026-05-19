"""Shared helpers for package hallucination dataset builders."""

import argparse
from datetime import date, datetime
import json
from pathlib import Path

STANDARD_FIELDS = ("text", "package_first_seen")
SUPPORTED_FORMATS = ("jsonl",)


def normalise_first_seen(first_seen):
    """Return an ISO-8601 date string for a package creation date, or None."""
    if first_seen is None:
        return None

    if isinstance(first_seen, datetime):
        return first_seen.date().isoformat()

    if isinstance(first_seen, date):
        return first_seen.isoformat()

    first_seen = str(first_seen).strip()
    if not first_seen:
        return None

    iso_candidate = first_seen
    if iso_candidate.endswith("Z"):
        iso_candidate = f"{iso_candidate[:-1]}+00:00"

    try:
        return datetime.fromisoformat(iso_candidate).date().isoformat()
    except ValueError:
        pass

    for date_format in (
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(first_seen, date_format).date().isoformat()
        except ValueError:
            continue

    return None


def emit_record(name, first_seen):
    """Build a standard Hugging Face JSONL row for package datasets."""
    return {
        STANDARD_FIELDS[0]: str(name),
        STANDARD_FIELDS[1]: normalise_first_seen(first_seen),
    }


def configure_argparse(description, default_output, default_input=None):
    """Build the standard CLI parser for package dataset builders."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--input",
        default=default_input,
        help="Optional local package-name source file.",
    )
    parser.add_argument(
        "--output",
        default=default_output,
        help="Path to write the generated dataset.",
    )
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default="jsonl",
        help="Output dataset format.",
    )
    return parser


def write_jsonl(records, output_path):
    """Write records to a JSONL file."""
    with Path(output_path).open("w", encoding="utf-8") as output_file:
        for record in records:
            json.dump(record, output_file, sort_keys=True)
            output_file.write("\n")
