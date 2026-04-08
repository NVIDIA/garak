#!/usr/bin/env python3
"""ATR (Agent Threat Rules) utilities for garak.

sync_rules:
    Fetches latest ATR rules from GitHub and writes them to
    ``garak/data/atr/rules.json`` (or the user's XDG data path).

generate_rule:
    Takes successful garak probe outputs and drafts an ATR rule YAML
    for review and submission to the ATR project.

Usage::

    # Sync latest rules (requires PyYAML: pip install pyyaml)
    python tools/atr.py sync

    # Generate draft rule from a hitlog
    python tools/atr.py generate --hitlog report/hitlog.jsonl --category prompt-injection
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path

logger = logging.getLogger(__name__)

def _default_output_path() -> Path:
    """Resolve XDG-based data path for ATR rules.

    Writes to the user's garak data directory so the detector picks
    it up via LocalDataPath's ORDERED_SEARCH_PATHS precedence.
    Falls back to package data dir if XDG is not available.
    """
    try:
        from garak import _config
        xdg_dir = _config.transient.data_dir / "data" / "atr"
        xdg_dir.mkdir(parents=True, exist_ok=True)
        return xdg_dir / "rules.json"
    except Exception:
        return Path(__file__).parent.parent / "garak" / "data" / "atr" / "rules.json"


def sync_rules(
    repo: str = "Agent-Threat-Rule/agent-threat-rules",
    branch: str = "main",
    output: Path | None = None,
    stdout: bool = False,
) -> int:
    """Fetch latest ATR rules from GitHub and write rules.json.

    Downloads the repo as a zip (no git dependency), parses YAML rules,
    and writes a compact JSON file for the detector to load.

    By default writes to the user's XDG data directory. Use --stdout
    to print JSON to stdout instead.

    Returns the number of patterns synced.
    """
    try:
        import yaml
    except ImportError:
        print("PyYAML required: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    dest = output or _default_output_path()
    url = f"https://github.com/{repo}/archive/refs/heads/{branch}.zip"

    print(f"Downloading {url} ...")
    with urllib.request.urlopen(url, timeout=30) as resp:
        zip_data = BytesIO(resp.read())

    result: dict[str, list[list[str]]] = {}
    with zipfile.ZipFile(zip_data) as zf:
        for name in sorted(zf.namelist()):
            if "/rules/" not in name or not name.endswith(".yaml"):
                continue
            content = zf.read(name).decode("utf-8")
            try:
                doc = yaml.safe_load(content)
            except yaml.YAMLError:
                continue
            if not doc or not doc.get("detection", {}).get("conditions"):
                continue
            cat = doc.get("tags", {}).get("category", "unknown")
            if cat not in result:
                result[cat] = []
            for cond in doc["detection"]["conditions"]:
                if cond.get("operator") == "regex" and cond.get("value"):
                    pat = re.sub(r"^\(\?[imsx]+\)", "", cond["value"])
                    result[cat].append([doc["id"], doc.get("severity", "medium"), pat])

    total = sum(len(v) for v in result.values())
    json_out = json.dumps(result, indent=2, ensure_ascii=True)

    if stdout:
        print(json_out)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json_out)
        print(f"Synced {total} patterns across {len(result)} categories -> {dest}")

    return total


def generate_rule(
    probe_outputs: list[str],
    category: str = "prompt-injection",
    severity: str = "high",
) -> str:
    """Generate an ATR rule YAML draft from successful probe outputs.

    Extracts common keywords from attack strings and builds a regex pattern.
    The output is a draft -- review before submitting to ATR.
    """
    if not probe_outputs:
        return ""

    word_counts: dict[str, int] = {}
    for text in probe_outputs:
        words = set(re.findall(r"\b[a-zA-Z]{4,}\b", text.lower()))
        for w in words:
            word_counts[w] = word_counts.get(w, 0) + 1

    threshold = max(2, len(probe_outputs) // 2)
    common_words = sorted(
        [w for w, c in word_counts.items() if c >= threshold],
        key=lambda w: word_counts[w],
        reverse=True,
    )[:6]

    if not common_words:
        return ""

    pattern = r"(?i)\b" + r"\b.*\b".join(re.escape(w) for w in common_words[:4]) + r"\b"
    date = datetime.now().strftime("%Y/%m/%d")
    rule_id = f"ATR-DRAFT-{hash(pattern) % 100000:05d}"

    return f"""title: "Garak-generated: {common_words[0]} pattern"
id: {rule_id}
rule_version: 1
status: draft
description: >
  Auto-generated from {len(probe_outputs)} successful Garak probe outputs.
  Common keywords: {', '.join(common_words[:6])}.
  REVIEW REQUIRED before adding to production ruleset.
author: "garak + ATR"
date: "{date}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: {severity}
tags:
  category: {category}
  subcategory: garak-generated
  confidence: low
agent_source:
  type: mcp_exchange
  framework: [any]
  provider: [any]
detection:
  conditions:
    - field: content
      operator: regex
      value: '{pattern}'
      description: "Pattern from {len(probe_outputs)} Garak probe outputs"
  condition: any
response:
  actions: [alert]
test_cases:
  true_positives:
    - input: "{probe_outputs[0][:100].replace(chr(34), chr(39))}"
      expected: triggered
"""


def main():
    parser = argparse.ArgumentParser(description="ATR utilities for garak")
    sub = parser.add_subparsers(dest="command")

    sync_p = sub.add_parser("sync", help="Sync latest ATR rules from GitHub")
    sync_p.add_argument("--repo", default="Agent-Threat-Rule/agent-threat-rules")
    sync_p.add_argument("--branch", default="main")
    sync_p.add_argument("--output", type=Path, default=None, help="Write to specific path")
    sync_p.add_argument("--stdout", action="store_true", help="Print JSON to stdout")

    gen_p = sub.add_parser("generate", help="Generate ATR rule from hitlog")
    gen_p.add_argument("--hitlog", type=Path, required=True)
    gen_p.add_argument("--category", default="prompt-injection")
    gen_p.add_argument("--severity", default="high")

    args = parser.parse_args()

    if args.command == "sync":
        sync_rules(args.repo, args.branch, args.output, getattr(args, "stdout", False))
    elif args.command == "generate":
        outputs = []
        with open(args.hitlog) as f:
            for line in f:
                entry = json.loads(line)
                for o in entry.get("outputs", []):
                    if o:
                        outputs.append(o)
        if outputs:
            print(generate_rule(outputs, args.category, args.severity))
        else:
            print("No outputs found in hitlog", file=sys.stderr)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
