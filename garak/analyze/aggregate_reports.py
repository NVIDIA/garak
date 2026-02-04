#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""aggregate multiple garak reports on the same generator

useful for e.g. assembling a report that's been run one probe at a time
"""

# cli params:
#   output file
#   input filespec

import datetime
import json
import uuid
import sys

import garak
import garak.analyze.report_digest


def _process_file_body(in_file, out_file, aggregate_uuid) -> dict | None:
    eof = False
    while not eof:
        line = in_file.readline()
        if not line:
            eof = True
            continue
        entry = json.loads(line.strip())
        if entry["entry_type"] == "digest":
            return entry  # quit at last line
        if entry["entry_type"] not in ("attempt", "eval"):
            continue
        if (
            entry["entry_type"] == "attempt" and entry["status"] != 2
        ):  # incomplete attempt, skip
            continue

        entry["uuid"] = aggregate_uuid
        out_file.write(json.dumps(entry, ensure_ascii=False) + "\n")


def model_target_depr_notice(entry):
    import garak.command

    garak.command.deprecation_notice(f"config plugins.{entry}", "0.13.1.pre1")


def _aggregate_probespec(filenames: list[str]) -> str:
    """
    One pass over jsonl files to aggregate probespecs from the first line in each
    """
    probespecs = set([])
    for filename in filenames:
        with open(filename, "r", encoding="utf8") as fd:
            setup_line = fd.readline()
            setup = json.loads(setup_line)
            assert setup["entry_type"] == "start_run setup"
            probespecs.add(setup["plugins.probe_spec"])
    return ",".join(sorted(probespecs))


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    import garak._config
    import argparse

    garak._config.load_config()
    print(
        f"garak {garak.__description__} v{garak._config.version} ( https://github.com/NVIDIA/garak )"
    )

    p = argparse.ArgumentParser(
        prog="python -m garak.analyze.aggregate_reports",
        description="Aggregate multiple similar garak reports into one JSONL",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    p.add_argument("-o", "--output_path", help="Output filename", required=True)
    p.add_argument("infiles", nargs="+", help="garak jsonl reports to be aggregated")
    a = p.parse_args(argv)

    # get the list of files
    in_filenames = a.infiles

    # get the header from the first file
    aggregate_uuid = str(uuid.uuid4())
    aggregate_starttime_iso = datetime.datetime.now().isoformat()

    print("writing aggregated data to", a.output_path)
    with open(a.output_path, "w+", encoding="utf-8") as out_file:
        lead_filename = in_filenames[0]
        print("lead file", in_filenames[0])
        probespecs = _aggregate_probespec(in_filenames)
        with open(in_filenames[0], "r", encoding="utf8") as lead_file:
            # extract model type, model name, garak version
            setup_line = lead_file.readline()
            setup = json.loads(setup_line)
            assert setup["entry_type"] == "start_run setup"
            if "plugins.model_type" in setup:
                model_target_depr_notice("plugins.model_type")
                setup["plugins.target_type"] = setup["plugins.model_type"]
            target_type = setup["plugins.target_type"]
            if "plugins.model_name" in setup:
                model_target_depr_notice("plugins.model_name")
                setup["plugins.target_name"] = setup["plugins.model_name"]
            target_name = setup["plugins.target_name"]
            version = setup["_config.version"]
            setup["aggregation"] = in_filenames
            setup["plugins.probe_spec"] = probespecs

            # write the header, completed attempts, and eval rows

            out_file.write(json.dumps(setup) + "\n")

            init_line = lead_file.readline()
            init = json.loads(init_line)
            assert init["entry_type"] == "init"
            assert init["garak_version"] == version

            orig_uuid = init["run"]
            init["orig_uuid"] = init["run"]
            init["run"] = aggregate_uuid

            init["orig_start_time"] = init["start_time"]
            init["start_time"] = aggregate_starttime_iso

            out_file.write(json.dumps(init) + "\n")

            _process_file_body(lead_file, out_file, aggregate_uuid)

        if len(in_filenames) > 1:
            # for each other file
            for subsequent_filename in in_filenames[1:]:
                print("processing", subsequent_filename)
                with open(subsequent_filename, "r", encoding="utf8") as subsequent_file:
                    # check the header, quit if not good

                    setup_line = subsequent_file.readline()
                    setup = json.loads(setup_line)
                    assert setup["entry_type"] == "start_run setup"
                    if "plugins.target_type" not in setup:
                        model_target_depr_notice("plugins.model_type")
                        setup["plugins.target_type"] = setup["plugins.model_type"]
                    if "plugins.target_name" not in setup:
                        model_target_depr_notice("plugins.model_name")
                        setup["plugins.target_name"] = setup["plugins.model_name"]
                    assert target_type == setup["plugins.target_type"]
                    assert target_name == setup["plugins.target_name"]
                    assert version == setup["_config.version"]

                    init_line = subsequent_file.readline()
                    init = json.loads(init_line)
                    assert init["entry_type"] == "init"
                    assert init["garak_version"] == version

                    # write the completed attempts and eval rows
                    _process_file_body(subsequent_file, out_file, aggregate_uuid)

    digest = garak.analyze.report_digest.build_digest(a.output_path)
    with open(a.output_path, "a+", encoding="utf-8") as out_file:
        garak.analyze.report_digest.append_report_object(out_file, digest)

    print("done")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
