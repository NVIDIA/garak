# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Definitions of commands and actions that can be run in the garak toolkit"""

import logging
import json
import random
import typing

HINT_CHANCE = 0.25


def hint(msg, logging=None):
    # sub-optimal, but because our logging setup is thin & uses the global
    # default, placing a top-level import can break logging - so we can't
    # assume `logging` is imported at this point.
    msg = f"⚠️  {msg}"
    if logging is not None:
        logging.info(msg)
    if random.random() < HINT_CHANCE:
        print(msg)


def start_logging():
    from garak import _config

    log_filename = _config.transient.log_filename

    logging.info("invoked")

    return log_filename


def start_run():
    import logging
    import os
    import uuid

    from pathlib import Path
    from garak import _config

    logging.info("run started at %s", _config.transient.starttime_iso)
    # print("ASSIGN UUID", args)
    if _config.system.lite and "probes" not in _config.transient.cli_args and not _config.transient.cli_args.list_probes and not _config.transient.cli_args.list_detectors and not _config.transient.cli_args.list_generators and not _config.transient.cli_args.list_buffs and not _config.transient.cli_args.list_config and not _config.transient.cli_args.plugin_info and not _config.run.interactive:  # type: ignore
        hint(
            "The current/default config is optimised for speed rather than thoroughness. Try e.g. --config full for a stronger test, or specify some probes.",
            logging=logging,
        )
    _config.transient.run_id = str(uuid.uuid4())  # uuid1 is safe but leaks host info
    report_path = Path(_config.reporting.report_dir)
    if not report_path.is_absolute():
        logging.debug("relative report dir provided")
        report_path = _config.transient.data_dir / _config.reporting.report_dir
    if not os.path.isdir(report_path):
        try:
            report_path.mkdir(mode=0o740, parents=True, exist_ok=True)
        except PermissionError as e:
            raise PermissionError(
                f"Can't create reporting directory {report_path}, quitting"
            ) from e

    filename = f"garak.{_config.transient.run_id}.report.jsonl"
    if not _config.reporting.report_prefix:
        filename = f"garak.{_config.transient.run_id}.report.jsonl"
    else:
        filename = _config.reporting.report_prefix + ".report.jsonl"
    _config.transient.report_filename = str(report_path / filename)
    _config.transient.reportfile = open(
        _config.transient.report_filename, "w", buffering=1, encoding="utf-8"
    )
    setup_dict = {"entry_type": "start_run setup"}
    for k, v in _config.__dict__.items():
        if k[:2] != "__" and type(v) in (
            str,
            int,
            bool,
            dict,
            tuple,
            list,
            set,
            type(None),
        ):
            setup_dict[f"_config.{k}"] = v
    for subset in "system transient run plugins reporting".split():
        for k, v in getattr(_config, subset).__dict__.items():
            if k[:2] != "__" and type(v) in (
                str,
                int,
                bool,
                dict,
                tuple,
                list,
                set,
                type(None),
            ):
                setup_dict[f"{subset}.{k}"] = v

    _config.transient.reportfile.write(json.dumps(setup_dict, ensure_ascii=False) + "\n")
    _config.transient.reportfile.write(
        json.dumps(
            {
                "entry_type": "init",
                "garak_version": _config.version,
                "start_time": _config.transient.starttime_iso,
                "run": _config.transient.run_id,
            }, ensure_ascii=False
        )
        + "\n"
    )
    logging.info("reporting to %s", _config.transient.report_filename)


def end_run():
    import datetime
    import logging

    from garak import _config

    logging.info("run complete, ending")
    end_object = {
        "entry_type": "completion",
        "end_time": datetime.datetime.now().isoformat(),
        "run": _config.transient.run_id,
    }
    _config.transient.reportfile.write(json.dumps(end_object, ensure_ascii=False) + "\n")
    _config.transient.reportfile.close()

    print(f"📜 report closed :) {_config.transient.report_filename}")
    if _config.transient.hitlogfile:
        _config.transient.hitlogfile.close()

    timetaken = (datetime.datetime.now() - _config.transient.starttime).total_seconds()

    digest_filename = _config.transient.report_filename.replace(".jsonl", ".html")
    print(f"📜 report html summary being written to {digest_filename}")
    try:
        write_report_digest(_config.transient.report_filename, digest_filename)
    except Exception as e:
        msg = "Didn't successfully build the report - JSON log preserved. " + repr(e)
        logging.exception(e)
        logging.info(msg)
        print(msg)

    msg = f"garak run complete in {timetaken:.2f}s"
    print(f"✔️  {msg}")
    logging.info(msg)


def print_plugins(prefix: str, color):
    from colorama import Style

    from garak._plugins import enumerate_plugins

    plugin_names = enumerate_plugins(category=prefix)
    plugin_names = [(p.replace(f"{prefix}.", ""), a) for p, a in plugin_names]
    module_names = set([(m.split(".")[0], True) for m, a in plugin_names])
    plugin_names += module_names
    for plugin_name, active in sorted(plugin_names):
        print(f"{Style.BRIGHT}{color}{prefix}: {Style.RESET_ALL}", end="")
        print(plugin_name, end="")
        if "." not in plugin_name:
            print(" 🌟", end="")
        if not active:
            print(" 💤", end="")
        print()


def print_probes():
    from colorama import Fore

    print_plugins("probes", Fore.LIGHTYELLOW_EX)


def print_detectors():
    from colorama import Fore

    print_plugins("detectors", Fore.LIGHTBLUE_EX)


def print_generators():
    from colorama import Fore

    print_plugins("generators", Fore.LIGHTMAGENTA_EX)


def print_buffs():
    from colorama import Fore

    print_plugins("buffs", Fore.LIGHTGREEN_EX)


# describe plugin
def plugin_info(plugin_name):
    from garak._plugins import plugin_info

    info = plugin_info(plugin_name)
    if len(info) > 0:
        print(f"Configured info on {plugin_name}:")
        priority_fields = ["description"]
        for k in priority_fields:
            if k in info:
                print(f"{k:>35}:", info[k])
        for k, v in info.items():
            if k in priority_fields:
                continue
            print(f"{k:>35}:", v)
    else:
        print(
            f"Plugin {plugin_name} not found. Try --list_probes, or --list_detectors."
        )


# TODO set config vars - debug, threshold
# TODO load generator
# TODO set probe config string


# do a run
def probewise_run(generator, probe_names, evaluator, buffs):
    import garak.harnesses.probewise

    probewise_h = garak.harnesses.probewise.ProbewiseHarness()
    probewise_h.run(generator, probe_names, evaluator, buffs)


def pxd_run(generator, probe_names, detector_names, evaluator, buffs):
    import garak.harnesses.pxd

    pxd_h = garak.harnesses.pxd.PxD()
    pxd_h.run(
        generator,
        probe_names,
        detector_names,
        evaluator,
        buffs,
    )


def _enumerate_obj_values(o):
    for i in dir(o):
        if i[:2] != "__" and not callable(getattr(o, i)):
            print(f"    {i}: {getattr(o, i)}")


def list_config():
    from garak import _config

    print("_config:")
    _enumerate_obj_values(_config)

    for section in "system transient run plugins reporting".split():
        print(f"{section}:")
        _enumerate_obj_values(getattr(_config, section))


def write_report_digest(report_filename, html_report_filename):
    from garak.analyze import report_digest

    digest = report_digest.build_digest(report_filename)
    with open(report_filename, "a+", encoding="utf-8") as report_file:
        report_digest.append_report_object(report_file, digest)
    html_report = report_digest.build_html(digest)
    with open(html_report_filename, "w", encoding="utf-8") as htmlfile:
        htmlfile.write(html_report)
