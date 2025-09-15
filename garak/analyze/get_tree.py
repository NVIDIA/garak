#!/usr/bin/env python

# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
import json
import sys
import argparse

from garak import __description__
from garak import _config


def get_tree(report_path: str) -> None:
    probes = set([])
    node_info = defaultdict(dict)

    with open(report_path, "r", encoding="utf-8") as reportfile:
        for line in reportfile:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r["entry_type"] == "tree_data":
                probe = r["probe"]
                probes.add(probe)
                node_info[probe][r["node_id"]] = r

    for probe in probes:
        print(f"============== {probe} ==============")

        node_children = defaultdict(list)
        for node in node_info[probe].values():
            node_children[node["node_parent"]].append(node["node_id"])

        # roots: those with parents not in node_info, or none
        roots = set([])
        for node in node_info[probe].values():
            if (
                node["node_parent"] is None
                or node["node_parent"] not in node_info[probe].keys()
            ):
                roots.add(node["node_id"])

        def print_tree(node_id, indent=0):
            forms = "" + ",".join(node_info[probe][node_id]["surface_forms"]) + ""
            print(
                "  " * indent + f"{forms} ::> {node_info[probe][node_id]['node_score']}",
            )
            children = node_children[node_id]
            if children:
                for child in children:
                    print_tree(child, indent + 1)

        for root in sorted(list(roots)):
            print_tree(root)


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    _config.load_config()
    print(
        f"garak {__description__} v{_config.version} ( https://github.com/NVIDIA/garak )"
    )

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.get_tree",
        description="Print a tree view from 'tree_data' entries in a garak JSONL report",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
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
    get_tree(report_path)


if __name__ == "__main__":
    main()
