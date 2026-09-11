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
import csv
import json
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


COLUMN_ORDER = ["probe", "prompt", "output", "detector", "score"]


def _write_csv(entries, output_file) -> None:
    writer = csv.DictWriter(
        output_file,
        fieldnames=COLUMN_ORDER,
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(entries)


def get_last(convs: list[dict]) -> tuple[list[str], list[str]]:
    user = list()
    assistant = list()
    for conv in convs:
        turns = conv["turns"]
        for turn in reversed(turns):
            if turn["role"] == "user":
                user.append(turn["content"]["text"])
            elif turn["role"] == "assistant":
                assistant.append(turn["content"]["text"])
            if len(user) == len(assistant):
                break

    return user, assistant


def tablify(report_path: str, output_path: str | None) -> None:
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
            conversations = record["conversations"]
            try:
                for detector_name, detector_scores in record[
                    "detector_results"
                ].items():
                    total_entries += 1
                    prompts, outputs = get_last(conversations)
                    if len(outputs) != len(prompts):
                        print(
                            f"Got {len(outputs)} outputs and {len(prompts)} prompts for {probe_name}. "
                            f"Results might be weird."
                        )
                    if len(outputs) != len(detector_scores):
                        none_free_outputs = [o for o in outputs if o is not None]
                        prompts = [p for p, o in zip(prompts, outputs) if o is not None]
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
                            outputs = none_free_outputs
                    for prompt, output, score in zip(prompts, outputs, detector_scores):
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
    if output_path is not None:
        with open(output_path, "w", encoding="utf-8", newline="") as output_file:
            _write_csv(table_entries, output_file)

        summary = (
            f"Evaluated {total_entries} entries. "
            f"Wrote {len(table_entries)} lines to {output_path}."
        )
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
        _write_csv(table_entries, sys.stdout)


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
