import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
import json
from pathlib import Path
import sys

import backoff
import requests

DEFAULT_OUTPUT_FILE = "pypi_packages.jsonl"

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


def get_all_packages():
    url = "https://pypi.org/simple/"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    packages = response.text.split("\n")
    return [pkg.split("/")[2] for pkg in packages if "a href" in pkg]


def get_packages_from_file(input_file):
    with Path(input_file).open("r", encoding="utf-8") as source_file:
        return [line.strip() for line in source_file if line.strip()]


@backoff.on_exception(
    backoff.expo,
    (requests.exceptions.RequestException, requests.exceptions.HTTPError),
    max_tries=5,
)
def get_package_first_seen(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()
    releases = data.get("releases", {})
    upload_times = [
        release_file.get("upload_time")
        for release_files in releases.values()
        for release_file in release_files
        if release_file.get("upload_time")
    ]
    if not upload_times:
        return None
    return min(upload_times)


def build_records(packages, batch_size=1000):
    total_packages = len(packages)
    processed = 0
    records = []
    batches = [
        packages[i : i + batch_size] for i in range(0, total_packages, batch_size)
    ]

    for batch in batches:
        batch_results = []
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            future_to_package = {
                executor.submit(get_package_first_seen, package): package
                for package in batch
            }

            for future in as_completed(future_to_package):
                package = future_to_package[future]
                try:
                    creation_date = future.result()
                except (
                    requests.RequestException,
                    ValueError,
                    KeyError,
                    TypeError,
                ) as e:
                    print(f"Error processing package '{package}': {e}", file=sys.stderr)
                    creation_date = None

                batch_results.append((package, creation_date))
                processed += 1
                if processed % 100 == 0 or processed == total_packages:
                    print(
                        f"Processed: {processed}/{total_packages} ({processed/total_packages*100:.2f}%)"
                    )

        records.extend(
            emit_record(package, creation_date)
            for package, creation_date in batch_results
        )
        print(
            f"Batch completed. Total processed: {processed}/{total_packages} ({processed/total_packages*100:.2f}%)"
        )
        print("*" * 50)

    return records


def main(argv=None):
    parser = configure_argparse(
        "Build a PyPI package hallucination dataset.",
        DEFAULT_OUTPUT_FILE,
    )
    args = parser.parse_args(argv)

    packages = get_packages_from_file(args.input) if args.input else get_all_packages()
    if not packages:
        print(
            "No PyPI packages found; refusing to write an empty dataset.",
            file=sys.stderr,
        )
        return 1

    print(f"Starting to process {len(packages)} PyPI packages...")
    records = build_records(packages)
    write_jsonl(records, args.output)
    print(f"Done! Results saved in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
