#!/usr/bin/env python3

# report probes per tag
# look for untagged probes
# look for tags without description entries

from collections import defaultdict
import importlib
import os
import sys
import argparse

from garak import __description__
from garak import _config, _plugins
from garak.data import path as data_path


def misp_report(include_untagged: bool = True) -> None:
    misp_resource_file = data_path / "misp_descriptions.tsv"
    misp_descriptions = {}
    if os.path.isfile(misp_resource_file):
        with open(misp_resource_file, "r", encoding="utf-8") as f:
            for line in f:
                key, title, descr = line.strip().split("\t")
                misp_descriptions[key] = (title, descr)

    probes_per_tag = defaultdict(list)

    for plugin_name, active in _plugins.enumerate_plugins("probes"):
        class_name = plugin_name.split(".")[-1]
        module_name = plugin_name.replace(f".{class_name}", "")
        m = importlib.import_module(f"garak.{module_name}")
        c = getattr(m, class_name)
        tags = c.tags
        if tags == [] and include_untagged:
            print(f"{plugin_name}: no tags defined")
        for tag in tags:
            if tag not in misp_descriptions:
                print(f"{plugin_name}: tag {tag} undefined in misp_descriptions.tsv")
            probes_per_tag[tag].append(plugin_name)

    for misp_tag in misp_descriptions.keys():
        if len(probes_per_tag[misp_tag]) == 0:
            print(f"{misp_tag}: zero probes testing this")
        else:
            if len(probes_per_tag[misp_tag]) == 1:
                print(f"{misp_tag}: only one probe testing this")
            probe_list = ", ".join(probes_per_tag[misp_tag]).replace(" probes.", " ")
            print(f"> {misp_tag}: {probe_list}")


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    _config.load_config()
    print(
        f"garak {__description__} v{_config.version} ( https://github.com/NVIDIA/garak )"
    )

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.misp",
        description="Report probes per MISP tag and tag coverage gaps",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    parser.add_argument(
        "-u",
        "--include_untagged",
        action="store_true",
        help="Also print probes without any tags",
    )
    args = parser.parse_args(argv)

    sys.stdout.reconfigure(encoding="utf-8")
    misp_report(include_untagged=args.include_untagged)


if __name__ == "__main__":
    main()
