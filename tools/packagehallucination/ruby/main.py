import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
import json
from pathlib import Path
import sys
import time

import backoff
import requests

DEFAULT_INPUT_FILE = "gems.txt"
DEFAULT_OUTPUT_FILE = "rubygems_packages.jsonl"
INPUT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Standalone helpers - kept inline so this tool runs without sibling deps.
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


def get_all_packages(input_file):
    with Path(input_file).open("r", encoding="utf-8") as source_file:
        return [
            line.strip().split(" (")[0]
            for line in source_file
            if line.strip().split(" (")[0]
        ]


@backoff.on_exception(
    backoff.expo,
    (requests.exceptions.RequestException, requests.exceptions.HTTPError),
    max_tries=5,
)
def get_package_first_seen(gem_name):
    url = f"https://rubygems.org/api/v1/versions/{gem_name}.json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()

    versions = response.json()
    if not versions:
        return None

    earliest_version = min(
        versions, key=lambda v: datetime.strptime(v["created_at"], INPUT_TIME_FORMAT)
    )
    return earliest_version.get("created_at")


def build_records(gems, batch_size=100):
    total_gems = len(gems)
    processed = 0
    included = 0
    errors = 0
    start_time = time.time()
    records = []
    batches = [gems[i : i + batch_size] for i in range(0, total_gems, batch_size)]

    for batch in batches:
        batch_results = []
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            future_to_gem = {
                executor.submit(get_package_first_seen, gem_name): gem_name
                for gem_name in batch
            }

            for future in as_completed(future_to_gem):
                gem_name = future_to_gem[future]
                try:
                    creation_date = future.result()
                    included += 1
                except (
                    requests.RequestException,
                    ValueError,
                    KeyError,
                    TypeError,
                ) as e:
                    print(f"Error processing gem '{gem_name}': {e}", file=sys.stderr)
                    creation_date = None
                    errors += 1

                batch_results.append((gem_name, creation_date))
                processed += 1

                if processed % 100 == 0 or processed == total_gems:
                    elapsed_time = time.time() - start_time
                    gems_per_second = processed / elapsed_time if elapsed_time else 0
                    estimated_remaining_time = (
                        (total_gems - processed) / gems_per_second
                        if gems_per_second
                        else 0
                    )

                    print(
                        f"Processed: {processed}/{total_gems} ({processed/total_gems*100:.2f}%)"
                    )
                    print(f"Included: {included}, Errors: {errors}")
                    print(f"Elapsed time: {elapsed_time:.2f} seconds")
                    print(
                        f"Estimated remaining time: {estimated_remaining_time:.2f} seconds"
                    )
                    print(f"Processing speed: {gems_per_second:.2f} gems/second")
                    print("-" * 50)

        records.extend(
            emit_record(gem_name, creation_date)
            for gem_name, creation_date in batch_results
        )
        print(
            f"Batch completed. Total processed: {processed}/{total_gems} ({processed/total_gems*100:.2f}%)"
        )
        print("*" * 50)

    print(f"Total gems processed: {processed}")
    print(f"Gems included: {included}")
    print(f"Gems with errors: {errors}")
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")
    return records


def main(argv=None):
    parser = configure_argparse(
        "Build a RubyGems package hallucination dataset.",
        DEFAULT_OUTPUT_FILE,
        DEFAULT_INPUT_FILE,
    )
    args = parser.parse_args(argv)

    gems = get_all_packages(args.input)
    if not gems:
        print(
            "No RubyGems packages found; refusing to write an empty dataset.",
            file=sys.stderr,
        )
        return 1

    print(f"Starting to process {len(gems)} gems...")
    records = build_records(gems)
    write_jsonl(records, args.output)
    print(f"Filtering complete. Results saved in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
