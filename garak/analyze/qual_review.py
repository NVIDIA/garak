#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# generate a qualitative review of a garak report
# highlight failing probes
# give ten +ve and ten -ve examples from failing probes
# takes report.jsonl, optional bag.json (e.g. data/calibration/calibration.json) as input

from collections import defaultdict
from contextlib import redirect_stdout
import json
import random
import sys

import garak
import garak.analyze
import garak.analyze.calibration
from garak.probes import Tier

PROBE_DETECTOR_SEP = "+"


def build_tiers() -> dict:
    from garak._plugins import enumerate_plugins, plugin_info

    tiers = {}
    for tier in Tier:
        tiers[tier] = []

    for plugin, _ in enumerate_plugins("probes"):
        details = plugin_info(plugin)
        _, plugin_name = plugin.split(".", 1)
        tiers[Tier(details["tier"])].append(plugin_name)

    return tiers


def build_review(report_path: str) -> dict:
    tiers = build_tiers()
    c = garak.analyze.calibration.Calibration()
    probe_detector_scores = {}
    pos_examples = defaultdict(list)
    neg_examples = defaultdict(list)

    with open(report_path, "r", encoding="utf-8") as report_file:
        g = (json.loads(line.strip()) for line in report_file if line.strip())
        total_key = None
        for record in g:
            if record["entry_type"] == "eval":
                if not total_key:
                    if "total_evaluated" in record:
                        total_key = "total_evaluated"
                    else:
                        total_key = "total"
                passrate = (
                    record["passed"] / record[total_key] if record[total_key] > 0 else 0
                )
                probe_module, probe_classname = record["probe"].split(".", 1)
                detector = record["detector"].replace("detector.", "")
                detector_module, detector_classname = detector.split(".", 1)
                z = c.get_z_score(
                    probe_module,
                    probe_classname,
                    detector_module,
                    detector_classname,
                    passrate,
                )
                probe_detector_scores[
                    f"{record['probe']}{PROBE_DETECTOR_SEP}{detector}"
                ] = {
                    "passrate": passrate,
                    "z": z,
                }
            elif record["entry_type"] == "attempt" and record["status"] == 2:
                results = record["detector_results"]
                for detector_name in results:
                    for i, score in enumerate(results[detector_name]):
                        try:
                            fields = [record["prompt"], record["outputs"][i]]
                            if "triggers" in record.get("notes", {}).keys():
                                fields.append(record["notes"]["triggers"])
                            if score > 0.5:
                                pos_examples[
                                    record["probe_classname"]
                                    + PROBE_DETECTOR_SEP
                                    + detector_name
                                ].append(fields)
                            else:
                                neg_examples[
                                    record["probe_classname"]
                                    + PROBE_DETECTOR_SEP
                                    + detector_name
                                ].append(fields)
                        except IndexError:
                            continue

    t1_probe_names = tiers[Tier.OF_CONCERN]
    t2_probe_names = tiers[Tier.COMPETE_WITH_SOTA]
    t1_results = []
    t2_results = []
    not_processed = []

    for probe_detector, scores in probe_detector_scores.items():
        probe_name = probe_detector.split(PROBE_DETECTOR_SEP)[0]
        passrate = scores["passrate"]
        z_score = scores["z"]

        entry = {
            "probe_detector": probe_detector,
            "passrate": passrate,
            "z": z_score,
            "failing_examples": pos_examples[probe_detector][
                :10
            ],  # expand as needed
            "passing_examples": neg_examples[probe_detector][
                :10
            ],  # expand as needed
        }

        if probe_name in t1_probe_names:
            issues = []
            if passrate < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG:
                issues.append(f"low pass rate {passrate:0.4f}")
            if (
                z_score is not None
                and z_score < garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG
            ):
                issues.append(f"low z {z_score:-0.4f}")
            entry["issues"] = issues
            t1_results.append(entry)

        elif probe_name in t2_probe_names:
            issues = []
            if (
                z_score is not None
                and z_score < garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG
            ):
                issues.append(f"low z {z_score:-0.4f}")
            entry["issues"] = issues
            t2_results.append(entry)

        else:
            not_processed.append(probe_detector)

    return {
        "source_filename": report_path,
        "tier_1_probe_results": t1_results,
        "tier_2_probe_results": t2_results,
        "not_processed": not_processed,
    }

def output_json(review_data: dict) -> str:
    return json.dumps(review_data, ensure_ascii=False)

def output_markdown(review_data: dict) -> str:
    lines = []
    lines.append("# garak Qualitative review")
    lines.append(
        "Analysis of failing & passing probes/detectors, grouped by tier, including prompt & response samples for failing entries"
    )
    lines.append(f"source filename: {review_data['source_filename']}\n")

    def _format_examples(title, examples):
        res = [f"\n#### {title}"]
        # We can shuffle the excerpt here to maintain previous random behavior
        excerpt = list(examples)
        random.shuffle(excerpt)
        for index, entry in enumerate(excerpt):
            if "failing" in title.lower():
                res.append(f"##### Example {index+1}\n")
            else:
                res.append("")
            res.append(f"  * **prompt**:\n```\n{repr(entry[0])}\n```\n")
            if len(entry) == 3:
                res.append(f"  * **trigger**:\n```\n{repr(entry[2])}\n```\n")
            res.append(f"  * **response**:\n```\n{repr(entry[1])}\n```\n")
        return "\n".join(res)

    lines.append("## Tier 1 probe results")
    for result in review_data["tier_1_probe_results"]:
        lines.append(f"\n### Probe and detector: {result['probe_detector']}")
        lines.append(f"\n\n * passrate: `{result['passrate']:0.4f}`")
        lines.append(f" * z: `{result['z']}`\n\n")

        if result.get("issues"):
            lines.append("Issues found:")
            for issue in result["issues"]:
                if "pass rate" in issue:
                    lines.append(f"* low pass rate `{result['passrate']:0.4f}`")
                elif "low z" in issue:
                    lines.append(f"* low z         `{result['z']:-0.4f}`")
            lines.append(_format_examples("Examples of responses marked failing", result["failing_examples"]))
            lines.append(_format_examples("Examples of responses marked passing", result["passing_examples"]))
        else:
            lines.append("All performance within bounds")

    lines.append("\n## Tier 2 probe results")
    for result in review_data["tier_2_probe_results"]:
        lines.append(f"\n### Probe and detector: {result['probe_detector']}")
        lines.append(f"\n\n * passrate: `{result['passrate']:0.4f}`")
        lines.append(f" * z: `{result['z']}`\n\n")

        if result.get("issues"):
            lines.append("Issues found:")
            for issue in result["issues"]:
                if "low z" in issue:
                    lines.append(f"* low z   `{result['z']:-0.4f}`")
            lines.append(_format_examples("Examples of responses marked failing", result["failing_examples"]))
            lines.append(_format_examples("Examples of responses marked passing", result["passing_examples"]))
        else:
            lines.append("All performance within bounds")

    lines.append("\n## Probe/detector pairs not processed:")
    for entry in review_data["not_processed"]:
        lines.append(f"* {entry}")

    return "\n".join(lines)


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    import argparse

    garak._config.load_config()
    banner = f"garak {garak.__description__} v{garak._config.version} ( https://github.com/NVIDIA/garak )"

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.qual_review",
        description="Qualitative review of failing/passing probes and detectors with sample prompts/responses",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    parser.add_argument(
        "-j",
        "--json_output",
        action="store_true",
        help="Utilize JSON output for this review",
    )
    parser.add_argument(
        "-o",
        "--output_path",
        required=False,
        help="Output path for review",
    )
    parser.add_argument(
        "-r",
        "--report_path",
        required=False,
        help="Path to the garak JSONL report",
    )
    parser.add_argument(
        "report_path_positional",
        nargs="?",
        help="Path to the garak JSONL report (positional)",
    )
    args = parser.parse_args(argv)
    report_path = args.report_path or args.report_path_positional
    if not report_path:
        parser.error("a report path is required (positional or -r/--report_path)")

    sys.stdout.reconfigure(encoding="utf-8")

    review_data = build_review(report_path)
    if args.json_output:
        payload = output_json(review_data)
        if args.output_path:
            with open(args.output_path, "w", encoding="utf-8") as outfile:
                outfile.write(payload)
        else:
            print(payload)
    elif args.output_path:
        with open(args.output_path, "w", encoding="utf-8") as outfile:
            with redirect_stdout(outfile):
                print(banner)
                print(output_markdown(review_data))
    else:
        print(banner)
        print(output_markdown(review_data))


if __name__ == "__main__":
    main()
