#!/usr/bin/env python
# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# highlight failing probes
# give ten +ve and ten -ve examples from failing probes
# takes report.jsonl, optional bag.json as input

from collections import defaultdict
import json
import random
import sys

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


tiers = build_tiers()
# load in the scores

c = garak.analyze.calibration.Calibration()
probe_detector_scores = {}
pos_examples = defaultdict(list)
neg_examples = defaultdict(list)

print("# garak Qualitative review")
print(
    "Analysis of failing & passing probes/detectors, grouped by tier, including prompt & response samples for failing entries"
)
print("source filename: ", sys.argv[1])

with open(sys.argv[1], "r", encoding="utf-8") as report_file:
    g = (json.loads(line.strip()) for line in open(sys.argv[1]) if line.strip())
    for record in g:
        if record["entry_type"] == "eval":
            passrate = record["passed"] / record["total"] if record["total"] > 0 else 0
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
                        if "triggers" in record["notes"].keys():
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


def _print_examples(probe_detector):
    print("\n#### Examples of responses marked failing")
    excerpt = pos_examples[probe_detector]
    random.shuffle(excerpt)
    for index, entry in enumerate(excerpt[0:10]):
        print(f"##### Example {index+1}")
        print()
        print("  * **prompt**:\n```\n" + repr(entry[0]) + "\n```\n")
        if len(entry) == 3:
            print("  * **trigger**:\n```\n" + repr(entry[2]) + "\n```\n")
        print("  * **response**:\n```\n" + repr(entry[1]) + "\n```\n")
        print()
    print("\n#### Examples of responses marked passing")
    excerpt = neg_examples[probe_detector]
    random.shuffle(excerpt)
    for entry in excerpt[0:10]:
        print()
        print("  * **prompt**:\n```\n" + repr(entry[0]) + "\n```\n")
        if len(entry) == 3:
            print("  * **trigger**:\n```\n" + repr(entry[2]) + "\n```\n")
        print("  * **response**:\n```\n" + repr(entry[1]) + "\n```\n")
        print()


print("## Tier 1 probe results")
t1_probe_names = tiers[Tier.OF_CONCERN]
for probe_detector in probe_detector_scores.keys():
    if probe_detector.split(PROBE_DETECTOR_SEP)[0] in t1_probe_names:
        z, passrate = (
            probe_detector_scores[probe_detector]["z"],
            probe_detector_scores[probe_detector]["passrate"],
        )
        print("\n### Probe and detector: " + probe_detector)
        print(f"\n\n * passrate: `{passrate:0.4f}`\n * z: `{z}`\n\n")
        if passrate < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG or (
            z is not None and z < garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG
        ):
            print("Issues found:")
            if passrate < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG:
                print(f"* low pass rate `{passrate:0.4f}`")
            if z is not None and z < garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG:
                print(f"* low z         `{z:-0.4f}`")
            _print_examples(probe_detector)
        else:
            print("All performance within bounds")

print("## Tier 2 probe results")
t2_probe_names = tiers[Tier.COMPETE_WITH_SOTA]
for probe_detector in probe_detector_scores.keys():
    if probe_detector.split(PROBE_DETECTOR_SEP)[0] in t2_probe_names:
        z, passrate = (
            probe_detector_scores[probe_detector]["z"],
            probe_detector_scores[probe_detector]["passrate"],
        )
        print("\n### Probe and detector: " + probe_detector)
        print(f"\n\n * passrate: `{passrate:0.4f}`\n * z: `{z}`\n\n")
        if z is not None and z < garak.analyze.RELATIVE_DEFCON_BOUNDS.BELOW_AVG:
            print("Issues found:")
            print(f"* low z   `{z:-0.4f}`")
            _print_examples(probe_detector)
        else:
            print("All performance within bounds")

print("\n## Probe/detector pairs not processed:")
t1_t2_probes = t1_probe_names + t2_probe_names
for entry in [
    probe_detector
    for probe_detector in probe_detector_scores.keys()
    if probe_detector.split(PROBE_DETECTOR_SEP)[0] not in t1_t2_probes
]:
    print("*", entry)
