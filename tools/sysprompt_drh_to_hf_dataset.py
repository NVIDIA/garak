#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convert a consolidated prompts JSON file from drh into a Hugging Face dataset saved to disk."""

import argparse
import json

from datasets import Dataset


COLUMNS = [
    "agentname",
    "creation_date",
    "is-agent",
    "is-single-turn",
    "json-schema",
    "personalised-system-prompt",
    "structured-output-generation",
    "systemprompt",
]


def load_prompts(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["prompts"]


# Columns whose values should be stored as booleans in the dataset.
BOOL_COLUMNS = {"is-agent", "is-single-turn"}


def _to_bool(value) -> bool | None:
    # source data stores these fields inconsistently
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def build_dataset(prompts: list[dict]) -> Dataset:
    rows = {col: [] for col in COLUMNS}
    for prompt in prompts:
        for col in COLUMNS:
            value = prompt.get(col)
            if col in BOOL_COLUMNS:
                value = _to_bool(value)
            elif value is not None:
                value = str(value)
            rows[col].append(value)
    return Dataset.from_dict(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert consolidated_prompts JSON to a Hugging Face dataset."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the consolidated prompts JSON file.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory path where the dataset will be saved.",
    )
    args = parser.parse_args()

    print(f"📥 loading prompts from {args.input!r}")
    prompts = load_prompts(args.input)
    print(f"📜 loaded {len(prompts)} prompts from {args.input!r}")

    dataset = build_dataset(prompts)
    print(f"📦 built dataset: {len(dataset)} rows, columns: {dataset.column_names}")

    dataset.save_to_disk(args.output)
    print(f"💾 dataset saved to {args.output!r}")


if __name__ == "__main__":
    main()
