# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Conduct a variety of checks and tests to assess the integrity of a garak report.jsonl file """

"""
inventory of tests:

* ✔️ version mismatch between report and garak 
* ✔️ report using dev version 
* ✔️ current version is dev version
* ✔️ probe_spec matches probes in attempts
* ✔️ attempt status 1 has matching status 2
* ✔️ attempts have enough unique generations
* ✔️ attempt run ID in setup run IDs
* ✔️ detection has correct cardinality in attempt status 2s
* ✔️ summary object is present
* ✔️ at least one z-score is listed
* ✔️ summary matches probes requested
* ✔️ run was completed
* ✔️ run is <6 months old (calibration freshness)
* ✔️ at least one eval statement per probe
* ✔️ eval totals = num status 2 attempts
* ✔️ eval passed+nones <= total prompts

"""

import argparse
from collections import defaultdict
import datetime
import json
import sys
from typing import Set

notes = []


def add_note(note: str) -> None:
    global notes
    notes.append(note)
    try:
        print("🔹", note)
    except BrokenPipeError:
        pass


def _is_dev_version(version: str) -> bool:
    return version.split(".")[-1].startswith("pre")


def _compare_sets(set1: Set, set2: Set, set1_name: str, set2_name) -> None:
    if set1.difference(set2):
        add_note(
            f"not all {set1_name} present in {set2_name}, missing: "
            + repr(set1.difference(set2))
        )
    if set2.difference(set1):
        add_note(
            f"not all {set2_name} present in {set1_name}, missing: "
            + repr(set2.difference(set1))
        )


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    import garak._config

    garak._config.load_config()
    print(
        f"garak {garak.__description__} v{garak._config.version} ( https://github.com/NVIDIA/garak )"
    )

    p = argparse.ArgumentParser(
        prog="python -m garak.analyze.aggregate_reports",
        description="Check integrity of a garak report.jsonl file",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    p.add_argument("-r", "--report_path", help="Report to analyze", required=True)
    a = p.parse_args(argv)

    garak_version: str = None
    report_garak_version: str = None
    configured_probe_spec = set()
    probes_requested = set()
    generations_requested: int = 0
    setup_run_ids = set()
    init_present = False
    attempt_status_1_ids = set()
    attempt_status_2_ids = set()
    attempt_status_1_per_probe = defaultdict(int)
    attempt_status_2_per_probe = defaultdict(int)
    num_attempt_stats_2_per_probe = {}
    probes_found_in_attempts_status_1 = set()
    probes_found_in_attempts_status_2 = set()
    probes_found_in_evals = set()
    complete: bool = False
    completion_id: str = None
    digest_exists: bool = False

    print(f"checking {a.report_path}")

    garak_version = garak._config.version
    if _is_dev_version(garak_version):
        add_note(
            f"check running in development garak version {garak_version}, implementation will depend on branch+commit"
        )

    with open(a.report_path, encoding="utf-8") as reportfile:
        for line in [line.strip() for line in reportfile if line.strip()]:
            try:
                r = json.loads(line)
            except json.decoder.JSONDecodeError as jde:
                add_note(f"invalid json entry starting '{line[:100]}' : " + repr(jde))
                continue
            match r["entry_type"]:
                case "start_run setup":
                    report_garak_version = r["_config.version"]
                    if _is_dev_version(garak_version):
                        add_note(
                            f"report generated under development garak version {garak_version}, implementation will depend on branch+commit"
                        )
                    if report_garak_version != garak_version:
                        add_note(
                            f"current and report garak version mismatch, {garak_version} vs. {report_garak_version}"
                        )
                    configured_probe_spec = r["plugins.probe_spec"]
                    probes_requested, __rejected = garak._config.parse_plugin_spec(
                        configured_probe_spec, "probes"
                    )
                    probes_requested = set(
                        [
                            _klassname.replace("probes.", "")
                            for _klassname in probes_requested
                        ]
                    )

                    generations_requested = r["run.generations"]
                    setup_run_ids = r["transient.run_id"]

                case "init":
                    init_present = True
                    if r["run"] not in setup_run_ids:
                        add_note(
                            "init run uuid not in setup run uuid(s), did aggregation go wrong?"
                        )
                    _start = datetime.datetime.fromisoformat(r["start_time"])
                    _now = datetime.datetime.now()
                    _delta = _now - _start
                    if _delta.days > 180:
                        add_note(
                            f"Run is old ({_delta.days} days), calibration may have shifted"
                        )

                case "attempt":
                    _attempt_uuid = r["uuid"]
                    _num_outputs = len(r["outputs"])
                    _probe_name = r["probe_classname"]
                    if _probe_name not in probes_requested:
                        add_note(
                            f"attempt {_attempt_uuid} using probe {_probe_name} not requested in config"
                        )
                    if _num_outputs != generations_requested:
                        add_note(
                            f"probe {_probe_name} attempt {_attempt_uuid} status:{r['status']} has {_num_outputs} outputs but {generations_requested} were requested"
                        )

                    match r["status"]:
                        case 1:
                            attempt_status_1_ids.add(_attempt_uuid)
                            probes_found_in_attempts_status_1.add(_probe_name)
                            attempt_status_1_per_probe[_probe_name] += 1
                        case 2:
                            attempt_status_2_ids.add(_attempt_uuid)
                            probes_found_in_attempts_status_2.add(_probe_name)
                            attempt_status_2_per_probe[_probe_name] += 1
                            for _detectorname, _results in r[
                                "detector_results"
                            ].items():
                                _resultcount = len(_results)
                                if _resultcount != _num_outputs:
                                    add_note(
                                        f"attempt has incorrect detection results for {_detectorname}, {_resultcount} results vs. {_num_outputs} outputs"
                                    )

                        case _:
                            add_note(
                                f"attempt uuid {_attempt_uuid} found with unexpected status:{r['status']}"
                            )

                case "eval":
                    _probename = r["probe"]
                    _detectorname = r["detector"]
                    probes_found_in_evals.add(_probename)
                    if r["total"] != attempt_status_2_per_probe[_probe_name]:
                        add_note(
                            f"eval entry for {_probe_name} {_detectorname} indicates {r['total']} instances but there were {attempt_status_2_per_probe[_probe_name]} status:2 attempts"
                        )
                    if r["passed"] + r["nones"] > r["total"]:
                        add_note(
                            f"More results than instances for {_probename} eval with {r['detector']}"
                            + repr(r)
                        )
                    if (
                        attempt_status_1_per_probe[_probename]
                        != attempt_status_2_per_probe[_probename]
                    ):
                        add_note(
                            f"attempt 1/2 count mismatch for {_probename} on {_detectorname}: {attempt_status_1_per_probe[_probename]} @ status:1, but {attempt_status_2_per_probe[_probename]} @ status:2"
                        )
                        attempt_status_2_per_probe[_probe_name] = 0

                case "completion":
                    complete = True
                    completion_id = r["run"]
                    if completion_id not in setup_run_ids:
                        add_note(
                            "completion run uuid not in setup run uuid(s), did aggregation go wrong?"
                        )

                case "digest":
                    digest_exists = True
                    if r["meta"]["garak_version"] != report_garak_version:
                        add_note(
                            f"digest was written with a different garak version ({r["meta"]["garak_version"]}) from the run ({report_garak_version})"
                        )
                    probes_in_digest = set()

                    _z_score_values_found = set([])
                    for groupname, group in r["eval"].items():
                        group_probe_names = group.keys()
                        probes_in_digest.update(group_probe_names)
                        for probename, probe_summary in group.items():
                            if probename == "_summary":
                                continue
                            for detectorname, detector_summary in probe_summary.items():
                                if detectorname == "_summary":
                                    continue
                                try:
                                    _z_score_values_found.add(
                                        detector_summary["relative_score"]
                                    )
                                except KeyError:
                                    add_note(
                                        f"Missing 'relative_score' entry in digest for {probename} {detectorname}, old version?"
                                    )

                    _z_score_floats = filter(
                        lambda f: isinstance(f, float), _z_score_values_found
                    )
                    if not len(list(_z_score_floats)):
                        add_note(
                            "No Z-scores/relative scores found. Maybe deliberate, maybe calibration broken"
                        )

                    probes_in_digest.remove("_summary")
                    if probes_in_digest != probes_requested:
                        _compare_sets(
                            probes_requested,
                            probes_in_digest,
                            "probes requested in config",
                            "probes listed in digest",
                        )
                    if probes_in_digest != probes_found_in_evals:
                        _compare_sets(
                            probes_found_in_evals,
                            probes_in_digest,
                            "probes evaluated",
                            "probes listed in digest",
                        )

                case _:
                    continue

    if not init_present:
        add_note("no 'init' entry, run may not have started - invalid config?")
    if not complete:
        add_note("no 'completion' entry, run incomplete or from very old version")
    if not digest_exists:
        add_note("no 'digest' entry, run incomplete or from old version")
    if probes_found_in_evals != probes_requested:
        _compare_sets(
            probes_requested,
            probes_found_in_evals,
            "probes requested in config",
            "probes evaluated",
        )
    if probes_requested != probes_found_in_attempts_status_1:
        _compare_sets(
            probes_requested,
            probes_found_in_attempts_status_1,
            "probes requested in config",
            "probes in status:1 entries",
        )
    if probes_requested != probes_found_in_attempts_status_2:
        _compare_sets(
            probes_requested,
            probes_found_in_attempts_status_2,
            "probes requested in config",
            "probes in status:2 entries",
        )
    if probes_found_in_attempts_status_1 != probes_found_in_evals:
        _compare_sets(
            probes_found_in_attempts_status_1,
            probes_found_in_evals,
            "probes in status:1 entries",
            "probes evaluated",
        )
    if probes_found_in_attempts_status_2 != probes_found_in_evals:
        _compare_sets(
            probes_found_in_attempts_status_2,
            probes_found_in_evals,
            "probes in status:2 entries",
            "probes evaluated",
        )
    if probes_found_in_attempts_status_1 != probes_found_in_attempts_status_2:
        _compare_sets(
            probes_found_in_attempts_status_1,
            probes_found_in_attempts_status_2,
            "probes in status:1 entries",
            "probes in status:2 entries",
        )
    if attempt_status_1_ids != attempt_status_2_ids:
        _compare_sets(
            attempt_status_1_ids,
            attempt_status_2_ids,
            "attempt status:1 entries",
            "attempt status:2 entries",
        )

    print("done")
    print(len(notes), "notes")


if __name__ == "__main__":
    main()
