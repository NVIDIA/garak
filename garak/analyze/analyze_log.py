#!/usr/bin/env python3

"""
analyze a garak report.jsonl log file

print out summary stats, and which prompts led to failures

usage:

./analyze_log.py <report.jsonl filename>

"""
import sys
import json
import argparse

import garak


def analyze_log(report_path: str) -> None:
    """Analyze a garak report.jsonl log file and print summary statistics.

    Args:
        report_path: Path to the JSONL report file to analyze

    Raises:
        FileNotFoundError: If the report file doesn't exist
        PermissionError: If the report file can't be read
        json.JSONDecodeError: If the JSON data is malformed
    """
    started_attempt_uuids = set()
    completed_attempt_uuids = set()

    current_probe_classname = None

    try:
        with open(report_path, "r", encoding="utf-8") as reportfile:
            for line_num, line in enumerate(reportfile, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping malformed JSON on line {line_num}: {e}")
                    continue

                if not isinstance(record, dict):
                    continue

                if "entry_type" not in record.keys():
                    continue

                if record["entry_type"] in ("config", "init"):
                    print("##", line)
                    continue

                elif record["entry_type"] == "attempt":
                    if record.get("status") == 1:  # started
                        started_attempt_uuids.add(record.get("uuid", ""))
                        continue

                    if record.get("status") == 2:
                        completed_attempt_uuids.add(record.get("uuid", ""))

                    probe_classname = record.get("probe_classname")
                    if probe_classname and probe_classname != current_probe_classname:
                        print("## PROBE:", probe_classname)
                        current_probe_classname = probe_classname

                    # for each detector, check for hits with improved error handling
                    detector_results = record.get("detector_results", {})
                    if detector_results:
                        for detector_name, detector_scores in detector_results.items():
                            if detector_scores and len(detector_scores) > 0:
                                normalised_scores = [
                                    1 if i >= 0.5 else 0
                                    for i in detector_scores
                                    if i is not None
                                ]
                                # are there any hits?
                                if sum(normalised_scores):
                                    # if so print prompt & hit rate
                                    hit_rate = sum(normalised_scores) / len(
                                        normalised_scores
                                    )
                                    prompt_repr = repr(record.get("prompt", ""))
                                    print(
                                        "\t".join(
                                            [
                                                current_probe_classname or "unknown",
                                                detector_name,
                                                f"{hit_rate:0.2%}",
                                                prompt_repr,
                                            ]
                                        )
                                    )

                elif record["entry_type"] == "eval":
                    eval_data = [
                        record.get("probe", "unknown"),
                        record.get("detector", "unknown"),
                        f"{record.get('passed', 0) / max(record.get('total', 1), 1):.4f}",
                        str(record.get("total", 0)),
                    ]
                    print("\t".join(eval_data))

    except FileNotFoundError:
        print(f"Error: Report file '{report_path}' not found.")
        raise
    except PermissionError:
        print(f"Error: Permission denied reading '{report_path}'.")
        raise
    except Exception as e:
        print(f"Error analyzing log file: {e}")
        raise

    if not started_attempt_uuids:
        print("## no attempts in log")
    else:
        completion_rate = len(completed_attempt_uuids) / len(started_attempt_uuids)
        print("##", len(started_attempt_uuids), "attempts started")
        print("##", len(completed_attempt_uuids), "attempts completed")
        print(f"## attempt completion rate {completion_rate:.0%}")


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    garak._config.load_config()
    print(
        f"garak {garak.__description__} v{garak._config.version} ( https://github.com/NVIDIA/garak )"
    )

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.analyze_log",
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
    args = parser.parse_args(argv)
    report_path = args.report_path_opt or args.report_path
    if not report_path:
        parser.error("a report path is required (positional or -r/--report_path)")

    sys.stdout.reconfigure(encoding="utf-8")
    analyze_log(report_path)


if __name__ == "__main__":
    main()
