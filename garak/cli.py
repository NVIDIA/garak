#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flow for invoking garak from the command line"""


def main(arguments=[]) -> None:
    import datetime

    from garak import __version__, __description__, _config

    _config.transient.starttime = datetime.datetime.now()
    _config.transient.starttime_iso = _config.transient.starttime.isoformat()
    _config.version = __version__
    _config.load_base_config()

    print(
        f"garak {__description__} v{_config.version} ( https://github.com/leondz/garak ) at {_config.transient.starttime_iso}"
    )

    import argparse

    parser = argparse.ArgumentParser(
        description="LLM safety & security scanning tool",
        epilog="See https://github.com/leondz/garak",
    )

    ## SYSTEM
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=_config.system.verbose,
        help="add one or more times to increase verbosity of output during runtime",
    )
    parser.add_argument(
        "--report_prefix",
        type=str,
        default=_config.system.report_prefix,
        help="Specify an optional prefix for the report and hit logs",
    )
    parser.add_argument(
        "--narrow_output",
        action="store_true",
        help="give narrow CLI output",
    )
    parser.add_argument(
        "--parallel_requests",
        type=int,
        default=_config.system.parallel_requests,
        help="How many generator requests to launch in parallel for a given prompt. Ignored for models that support multiple generations per call.",
    )
    parser.add_argument(
        "--parallel_attempts",
        type=int,
        default=_config.system.parallel_attempts,
        help="How many probe attempts to launch in parallel.",
    )

    ## RUN
    parser.add_argument(
        "--seed", "-s", type=int, default=_config.run.seed, help="random seed"
    )
    parser.add_argument(
        "--deprefix",
        action="store_false",
        help="remove the prompt from the front of generator output",
    )
    parser.add_argument(
        "--eval_threshold",
        type=float,
        default=_config.system.eval_threshold,
        help="minimum threshold for a successful hit",
    )
    parser.add_argument(
        "--generations",
        "-g",
        type=int,
        default=_config.run.generations,
        help="number of generations per prompt",
    )
    parser.add_argument(
        "--config", type=str, default=None, help="YAML config file for this run"
    )

    ## PLUGINS
    # generator
    parser.add_argument(
        "--model_type",
        "-m",
        type=str,
        help="module and optionally also class of the generator, e.g. 'huggingface', or 'openai'",
    )
    parser.add_argument(
        "--model_name",
        "-n",
        type=str,
        default=None,
        help="name of the model, e.g. 'timdettmers/guanaco-33b-merged'",
    )
    generator_args = parser.add_mutually_exclusive_group()
    generator_args.add_argument(
        "--generator_option_file",
        "-G",
        type=str,
        help="path to JSON file containing options to pass to generator",
    )
    generator_args.add_argument(
        "--generator_options",
        type=str,
        help="options to pass to the generator",
    )
    # probes
    parser.add_argument(
        "--probes",
        "-p",
        type=str,
        default=_config.plugins.probe_spec,
        help="list of probe names to use, or 'all' for all (default).",
    )
    probe_args = parser.add_mutually_exclusive_group()
    probe_args.add_argument(
        "--probe_option_file",
        "-P",
        type=str,
        help="path to JSON file containing options to pass to probes",
    )
    probe_args.add_argument(
        "--probe_options",
        type=str,
        help="options to pass to probes, formatted as a JSON dict",
    )
    # detectors
    parser.add_argument(
        "--detectors",
        "-d",
        type=str,
        default=_config.plugins.detector_spec,
        help="list of detectors to use, or 'all' for all. Default is to use the probe's suggestion.",
    )
    parser.add_argument(
        "--extended_detectors",
        action="store_true",
        help="If detectors aren't specified on the command line, should we run all detectors? (default is just the primary detector, if given, else everything)",
    )
    # buffs
    parser.add_argument(
        "--buff",
        "-b",
        type=str,
        default=_config.plugins.buff_spec,
        help="buff to use",
    )

    ## COMMANDS
    parser.add_argument(
        "--plugin_info",
        type=str,
        help="show info about one plugin; format as type.plugin.class, e.g. probes.lmrc.Profanity",
    )
    parser.add_argument(
        "--list_probes", action="store_true", help="list available vulnerability probes"
    )
    parser.add_argument(
        "--list_detectors", action="store_true", help="list available detectors"
    )
    parser.add_argument(
        "--list_generators",
        action="store_true",
        help="list available generation model interfaces",
    )
    parser.add_argument(
        "--list_buffs",
        action="store_true",
        help="list available buffs/fuzzes",
    )
    parser.add_argument(
        "--version", "-V", action="store_true", help="print version info & exit"
    )
    parser.add_argument(
        "--report",
        "-r",
        type=str,
        help="process garak report into a list of AVID reports",
    )
    parser.add_argument(
        "--interactive",
        "-I",
        action="store_true",
        help="Enter interactive probing mode",
    )
    parser.add_argument(
        "--generate_autodan",
        action="store_true",
        help="generate AutoDAN prompts; requires --prompt_options with JSON containing a prompt and target",
    )

    import garak.command as command
    import logging

    command.start_logging()

    logging.debug("args - raw argument string received: %s", arguments)

    args = parser.parse_args(arguments)
    logging.debug("args - full argparse: %s", args)

    # load site config before loading CLI config
    _config.load_config(run_config_filename=args.config)

    # extract what was actually passed on CLI
    aux_parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    for arg, val in vars(args).items():
        if isinstance(val, bool):
            if val:
                aux_parser.add_argument("--" + arg, action="store_true")
            else:
                aux_parser.add_argument("--" + arg, action="store_false")
        else:
            aux_parser.add_argument("--" + arg)

    # cli_args contains items specified on CLI; the rest not to be overridden
    cli_args, _ = aux_parser.parse_known_args(arguments)

    # exception: action=count. only verbose uses this, let's bubble it through
    cli_args.verbose = args.verbose

    # also force command vars through to cli_args, even if false, to make command code easier
    command_options = "list_detectors list_probes list_generators list_buffs plugin_info interactive report version".split()
    for command_option in command_options:
        setattr(cli_args, command_option, getattr(args, command_option))

    logging.debug("args - cli_args&commands stored: %s", cli_args)

    print("ARGS", args)
    print("CLI_ARGS w commands", cli_args)
    del args
    args = cli_args

    import sys
    import importlib
    import json
    import uuid

    import garak.evaluators
    from garak._plugins import enumerate_plugins

    # startup
    if not args.version and not args.report:
        logging.info("started at %s", _config.transient.starttime_iso)
        _config.transient.run_id = str(
            uuid.uuid4()
        )  # uuid1 is safe but leaks host info
        if not _config.system.report_prefix:
            report_filename = f"garak.{_config.transient.run_id}.report.jsonl"
        else:
            report_filename = _config.system.report_prefix + ".report.jsonl"
        _config.transient.reportfile = open(
            report_filename, "w", buffering=1, encoding="utf-8"
        )
        args.__dict__.update({"entry_type": "args config"})
        _config.transient.reportfile.write(json.dumps(args.__dict__) + "\n")
        _config.transient.reportfile.write(
            json.dumps(
                {
                    "entry_type": "init",
                    "garak_version": _config.version,
                    "start_time": _config.transient.starttime_iso,
                    "run": _config.transient.run_id,
                }
            )
            + "\n"
        )
        logging.info("reporting to %s", report_filename)

    # save args info into config
    # need to know their type: plugin, system, or run
    # ignore params not listed here
    # - sorry, this means duping stuff, i know. maybe better argparse setup will help
    system_params = "verbose report_prefix narrow_output parallel_requests parallel_attempts".split()
    run_params = "seed deprefix eval_threshold generations"
    plugin_params = "model_type model_name extended_detectors".split()
    ignored_params = []
    for param, value in args._get_kwargs():
        if param in system_params:
            setattr(_config.system, param, value)
        elif param in run_params:
            setattr(_config.run, param, value)
        elif param in plugin_params:
            setattr(_config.plugins, param, value)
        else:
            ignored_params.append((param, value))

    # do a special thing for probe spec, detector spec, buff spec
    # what's the special thing? put the spec into the _spec config value, if set at cli
    _config.plugins.probe_spec = args.probes
    _config.plugins.detector_spec = args.detectors
    _config.plugins.buff_spec = args.buff

    # do a special thing for probe options, generator options
    if _config.plugins.probe_options:
        try:
            _config.probe_options = json.loads(_config.plugins.probe_options)
        except Exception as e:
            logging.warn("Failed to parse JSON probe_options:", e.args[0])

    # -- after this point, args is only authoritative wrt. command choices

    # process commands
    if args.interactive:
        from garak.interactive import interactive_mode

        try:
            interactive_mode()
        except Exception as e:
            logging.error(e)
            print(e)
            sys.exit(1)

    if args.version:
        pass

    elif args.plugin_info:
        command.plugin_info(args.plugin_info)

    elif args.list_probes:
        command.print_probes()

    elif args.list_detectors:
        command.print_detectors()

    elif args.list_buffs:
        command.print_buffs()

    elif args.list_generators:
        command.print_generators()

    elif args.report:
        from garak.report import Report

        report_location = args.report
        print(f"📜 Converting garak reports {report_location}")
        report = Report(args.report).load().get_evaluations()
        report.export()
        print(f"📜 AVID reports generated at {report.write_location}")

    # model is specified, we're doing something
    # should also trigger if _config.run.model_type is set, sooooo..
    # .. let's make this test happen /after/ the run config is loaded
    elif _config.run.model_type:
        command.start_run(args)

        if (
            hasattr(_config.plugins, "probe_option_file")
            or _config.plugins.probe_options
        ):
            if hasattr(_config.plugins, "probe_option_file"):
                with open(_config.plugins.probe_option_file, encoding="utf-8") as f:
                    probe_options_json = f.read().strip()
            elif _config.plugins.probe_options:
                probe_options_json = _config.plugins.probe_options
            try:
                _config.plugins.probe_options = json.loads(probe_options_json)
            except json.decoder.JSONDecodeError as e:
                logging.warning("Failed to parse JSON probe_options: %s", {e.args[0]})
                raise e

        if (
            hasattr(_config.plugins, "generator_option_file")
            or _config.plugins.generator_options
        ):
            if hasattr(_config.plugins, "generator_option_file"):
                with open(_config.plugins.generator_option_file, encoding="utf-8") as f:
                    generator_options_json = f.read().strip()
            elif _config.plugins.generator_options:
                generator_options_json = _config.run.generator_options
            try:
                _config.plugins.generator_options = json.loads(generator_options_json)
            except json.decoder.JSONDecodeError as e:
                logging.warning(
                    "Failed to parse JSON generator_options: %s", {e.args[0]}
                )
                raise e

        if (
            _config.plugins.model_type in ("openai", "replicate", "ggml", "huggingface")
            and not _config.plugins.model_name
        ):
            message = f"⚠️  Model type '{_config.plugins.model_type}' also needs a model name\n You can set one with e.g. --model_name \"billwurtz/gpt-1.0\""
            logging.error(message)
            raise ValueError(message)
        print(f"📜 reporting to {report_filename}")
        generator_module_name = args.model_type.split(".")[0]
        generator_mod = importlib.import_module(
            "garak.generators." + generator_module_name
        )
        if "." not in _config.plugins.model_type:
            if generator_mod.default_class:
                generator_class_name = generator_mod.default_class
            else:
                raise ValueError(
                    "module {generator_module_name} has no default class; pass module.ClassName to --model_type"
                )
        else:
            generator_class_name = _config.plugins.model_type.split(".")[1]

        if not args.model_name:
            generator = getattr(generator_mod, generator_class_name)()
        else:
            generator = getattr(generator_mod, generator_class_name)(
                _config.plugins.model_name
            )
        generator.generations = args.generations
        generator.seed = args.seed

        if args.generate_autodan:
            from garak.resources.autodan import autodan_generate

            try:
                prompt = _config.probe_options["prompt"]
                target = _config.probe_options["target"]
            except Exception as e:
                print(
                    "AutoDAN generation requires --probe_options with a .json containing a `prompt` and `target` "
                    "string"
                )
            autodan_generate(generator=generator, prompt=prompt, target=target)

        if _config.plugins.probe_spec == "all":
            probe_names = [
                name
                for name, active in enumerate_plugins(category="probes")
                if active == True
            ]
        else:
            probe_names = []
            for probe_clause in _config.plugins.probe_spec.split(","):
                if probe_clause.count(".") < 1:
                    probe_names += [
                        p
                        for p, a in enumerate_plugins(category="probes")
                        if p.startswith(f"probes.{probe_clause}.") and a == True
                    ]
                else:
                    probe_names += ["probes." + probe_clause]

        evaluator = garak.evaluators.ThresholdEvaluator(_config.run.eval_threshold)

        detector_names = []
        if (
            _config.plugins.detector_spec == ""
            or _config.plugins.detector_spec == "auto"
        ):
            pass
        elif _config.plugins.detector_spec == "all":
            detector_names = [
                name
                for name, active in enumerate_plugins(category="detectors")
                if active == True
            ]
        else:
            detector_clauses = _config.plugins.detector_spec.split(",")
            for detector_clause in detector_clauses:
                if detector_clause.count(".") < 1:
                    detector_names += [
                        d
                        for d, a in enumerate_plugins(category="detectors")
                        if d.startswith(f"detectors.{detector_clause}.") and a == True
                    ]
                else:
                    detector_names += ["detectors." + detector_clause]

        if args.buff:
            buffs = [args.buff]
        else:
            buffs = []

        if detector_names == []:
            command.probewise_run(generator, probe_names, evaluator, buffs)

        else:
            command.pxd_run(generator, probe_names, detector_names, evaluator, buffs)

        command.end_run()

    else:
        print("nothing to do 🤷  try --help")
        if _config.run.model_name and not _config.run.model_type:
            print(
                "💡 try setting --model_type (--model_name is currently set but not --model_type)"
            )
        logging.info("nothing to do 🤷")
