#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
count the number of characters sent and received based on prompts, outputs, and generations

should probably be upgraded to estimate token counts, too

usage

./count_tokens.py -r <report.jsonl filename>
"""

import json
import sys

import garak


def _to_text(value) -> str:
    """Extract text from report values while tolerating legacy shapes."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "content", "response"):
            nested = value.get(key)
            if isinstance(nested, (str, dict)):
                return _to_text(nested)
    return str(value)


def count_tokens(report_path: str) -> None:
    calls = 0
    input_length = 0
    output_length = 0
    generations = 10

    with open(report_path, encoding="utf-8") as reportfile:
        for line in reportfile:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if "run.generations" in r:
                generations = r["run.generations"]
                continue
            if "status" in r and r["status"] == 2:
                input_length += len(_to_text(r["prompt"])) * generations
                calls += generations
                outputs = r.get("outputs", [])
                if isinstance(outputs, list):
                    output_text = "".join(_to_text(o) for o in outputs)
                else:
                    output_text = str(outputs)
                output_length += len(output_text)

    print(f"Calls: {calls}")
    print(f"Input chars: {input_length}")
    print(f"Output chars: {output_length}")


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    import argparse

    garak._config.load_config()
    print(
        f"garak {garak.__description__} v{garak._config.version} ( https://github.com/NVIDIA/garak )"
    )

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.count_tokens",
        description="Count approximate token-like character totals from a garak JSONL report",
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
    count_tokens(report_path)


if __name__ == "__main__":
    main()
