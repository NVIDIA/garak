from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys

import backoff
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import configure_argparse, emit_record, write_jsonl  # noqa: E402

DEFAULT_OUTPUT_FILE = "pypi_packages.jsonl"


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
