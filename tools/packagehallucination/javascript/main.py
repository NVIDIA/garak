from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import sys
import time

import backoff
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import configure_argparse, emit_record, write_jsonl  # noqa: E402

DEFAULT_INPUT_FILE = "names.json"
DEFAULT_OUTPUT_FILE = "npm_packages.jsonl"


def get_all_packages(input_file):
    with Path(input_file).open("r", encoding="utf-8") as source_file:
        package_names = json.load(source_file)

    return [package_name for package_name in package_names if package_name]


@backoff.on_exception(
    backoff.expo,
    (requests.exceptions.RequestException, requests.exceptions.HTTPError),
    max_tries=5,
)
def get_package_first_seen(package_name):
    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()
    return data.get("time", {}).get("created")


def build_records(package_names, batch_size=1000):
    total_packages = len(package_names)
    processed = 0
    included = 0
    errors = 0
    start_time = time.time()
    records = []
    batches = [
        package_names[i : i + batch_size]
        for i in range(0, len(package_names), batch_size)
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
                    included += 1
                except (
                    requests.RequestException,
                    ValueError,
                    KeyError,
                    TypeError,
                ) as e:
                    print(f"Error processing package '{package}': {e}", file=sys.stderr)
                    creation_date = None
                    errors += 1

                batch_results.append((package, creation_date))
                processed += 1

        records.extend(
            emit_record(package, creation_date)
            for package, creation_date in batch_results
        )

        elapsed_time = time.time() - start_time
        packages_per_second = processed / elapsed_time if elapsed_time else 0
        estimated_remaining_time = (
            (total_packages - processed) / packages_per_second
            if packages_per_second
            else 0
        )

        print(
            f"Processed: {processed}/{total_packages} ({processed/total_packages*100:.2f}%)"
        )
        print(f"Included: {included}, Errors: {errors}")
        print(f"Elapsed time: {elapsed_time:.2f} seconds")
        print(f"Estimated remaining time: {estimated_remaining_time:.2f} seconds")
        print(f"Processing speed: {packages_per_second:.2f} packages/second")
        print("-" * 50)

    print(f"Total packages processed: {processed}")
    print(f"Packages included: {included}")
    print(f"Packages with errors: {errors}")
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")
    return records


def main(argv=None):
    parser = configure_argparse(
        "Build an npm package hallucination dataset.",
        DEFAULT_OUTPUT_FILE,
        DEFAULT_INPUT_FILE,
    )
    args = parser.parse_args(argv)

    package_names = get_all_packages(args.input)
    if not package_names:
        print(
            "No npm packages found; refusing to write an empty dataset.",
            file=sys.stderr,
        )
        return 1

    print(f"Starting to process {len(package_names)} npm packages...")
    records = build_records(package_names)
    write_jsonl(records, args.output)
    print(f"Filtering complete. Results saved in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
