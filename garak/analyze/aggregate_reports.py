#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""aggregate multiple garak reports on the same generator

useful for e.g. assembling a report that's been run one probe at a time
"""

# cli params:
#   output file
#   input filespec

import argparse
import datetime
import json
import uuid


def _process_file_body(in_file, out_file, aggregate_uuid):
    eof = False
    while not eof:
        line = in_file.readline()
        if not line:
            eof = True
            continue
        entry = json.loads(line.strip())
        if entry["entry_type"] not in ("attempt", "eval"):
            continue
        if (
            entry["entry_type"] == "attempt" and entry["status"] != 2
        ):  # incomplete attempt, skip
            continue

        entry["uuid"] = aggregate_uuid
        out_file.write(json.dumps(entry, ensure_ascii=False) + "\n")


p = argparse.ArgumentParser(
    description="aggregate multiple similar garak reports into one jsonl"
)
p.add_argument("-o", help="output filename", required=True)
p.add_argument("infiles", nargs="+", help="garak jsonl reports to be aggregated")
a = p.parse_args()

# get the list of files
in_filenames = a.infiles

# get the header from the first file
# start_run setup
# init
#  attempt status 1
#  attempt status 2
#  eval

aggregate_uuid = str(uuid.uuid4())
aggregate_starttime_iso = datetime.datetime.now().isoformat()

print("writing aggregated data to", a.o)
with open(a.o, "w", encoding="utf-8") as out_file:
    print("lead file", in_filenames[0])
    with open(in_filenames[0], "r", encoding="utf8") as lead_file:
        # extract model type, model name, garak version

        setup_line = lead_file.readline()
        setup = json.loads(setup_line)
        assert setup["entry_type"] == "start_run setup"
        model_type = setup["plugins.model_type"]
        model_name = setup["plugins.model_name"]
        version = setup["_config.version"]
        setup["aggregation"] = in_filenames

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
                assert model_type == setup["plugins.model_type"]
                assert model_name == setup["plugins.model_name"]
                assert version == setup["_config.version"]

                init_line = subsequent_file.readline()
                init = json.loads(init_line)
                assert init["entry_type"] == "init"
                assert init["garak_version"] == version

                # write the completed attempts and eval rows
                _process_file_body(subsequent_file, out_file, aggregate_uuid)

print("done")
