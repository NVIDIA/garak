#!/usr/bin/env python3

"""
Turn a garak report .jsonl file into a tabular data structure.
Prompt-response pairs are deduplicated for unique probe-detector combinations.
As an example, if the same prompt gets the same response 5 times (generations=5),
it will appear only once for each detector.

If an output CSV filename is not provided, it will pipe to stdout.

usage:
    ./tablify.py -r <report.jsonl filename> -o <output .csv filename>

"""
import sys
import json
import pandas as pd
import argparse


def make_hashable(obj):
    """
    Make mostly whatever thing you put into it hashable.

    Caveat: this can make objects like {"a": "b"} equal to objects like {("a", "b")}, which is simply not true but
    is sufficient for our case.
    """
    if isinstance(obj, dict):
        return frozenset((k, make_hashable(v)) for k, v in obj.items())
    elif isinstance(obj, list):
        return tuple(make_hashable(elem) for elem in obj)
    elif isinstance(obj, set):
        return frozenset(make_hashable(elem) for elem in obj)
    else:
        return obj


def tablify(report_path: str, output_path: str) -> None:
    line_entries = set()
    errored_probes = set()
    errored_entries = 0
    total_entries = 0
    with open(report_path, "r", encoding="utf-8") as reportfile:
        for line_number, line in enumerate(reportfile.readlines()):
            line = line.strip()

            # Exclude blank lines
            if not line:
                continue

            record = json.loads(line)

            # Exclude things that aren't valid json objects
            if not isinstance(record, dict):
                continue

            # Exclude things that aren't attempts
            if "entry_type" not in record.keys() or record["entry_type"] != "attempt":
                continue

            # Exclude attempts that aren't completed
            if "status" not in record.keys() or record["status"] != 2:
                continue

            # Exclude attempts without detector results
            if (
                "detector_results" not in record.keys()
                or not record["detector_results"]
            ):
                continue

            # At this point, we should have only completed runs with detector results.
            probe_name = record["probe_classname"]
            prompt = record["prompt"]
            outputs = record["outputs"]
            try:
                for detector_name, detector_scores in record[
                    "detector_results"
                ].items():
                    total_entries += 1
                    if len(outputs) != len(detector_scores):
                        none_free_outputs = [o for o in outputs if o is not None]
                        if len(none_free_outputs) != len(detector_scores):
                            errored_entries += 1
                            if probe_name not in errored_probes:
                                errored_probes.add(probe_name)
                                if output_path is not None:
                                    print(
                                        f"Encountered an error parsing results for {probe_name}. "
                                        f"These results will not be written."
                                    )
                        else:
                            record["outputs"] = none_free_outputs
                    for output, score in zip(outputs, detector_scores):
                        entry = {
                            "probe": probe_name,
                            "prompt": prompt,
                            "output": output,
                            "detector": detector_name,
                            "score": score,
                        }
                        hashable_entry = make_hashable(entry)
                        line_entries.add(hashable_entry)
            except ValueError as e:
                if output_path is not None:
                    print(
                        f"Encountered ValueError when trying to unpack {record['detector_results']}"
                    )
                continue
    table_entries = [dict(entry) for entry in line_entries]
    table_df = pd.DataFrame(table_entries)
    column_order = ["probe", "prompt", "output", "detector", "score"]
    table_df = table_df.reindex(columns=column_order)
    if output_path is not None:
        table_df.to_csv(output_path, index=False)

        summary = f"Evaluated {total_entries} entries. Wrote {len(table_df)} lines to {output_path}."
        if errored_entries > 0:
            if len(errored_probes) > 1:
                probes_with_errors = ", ".join(errored_probes)
            else:
                probes_with_errors = errored_probes.pop()
            summary = (
                summary
                + f" Encountered {errored_entries} entries with errors for probe(s): {probes_with_errors}."
            )
        print(summary)
    else:
        table_df.to_csv(path_or_buf=sys.stdout, index=False)


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.tablify",
        description="Analyze a garak JSONL report and emit summary lines",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    # Support both positional and -r/--report_path for backward compatibility
    parser.add_argument("report_path", nargs="?", help="Path to the garak JSONL report")
    parser.add_argument(
        "-r",
        "--report_path",
        dest="report_path_opt",
        help="Path to the garak JSONL report",
    )
    parser.add_argument(
        "-o",
        "--output_path",
        nargs="?",
        help="Path to write CSV output. Will default to stdout if no filename is provided.",
    )
    args = parser.parse_args(argv)
    report_path = args.report_path_opt or args.report_path
    if not report_path:
        parser.error("a report path is required (positional or -r/--report_path)")

    tablify(report_path, args.output_path)


if __name__ == "__main__":
    main()
