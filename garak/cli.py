# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flow for invoking garak from the command line"""

command_options = "list_detectors list_probes list_generators list_buffs list_config plugin_info interactive report version fix list_runs delete_run".split()


def str_to_bool(value):
    """Convert string to boolean for CLI arguments."""
    if isinstance(value, bool):
        return value
    if value.lower() in ("true", "1", "yes", "y"):
        return True
    elif value.lower() in ("false", "0", "no", "n"):
        return False
    else:
        raise argparse.ArgumentTypeError(f"Boolean value expected. Got: {value}")


def parse_cli_plugin_config(plugin_type, args):
    import os
    import json
    import logging

    opts_arg = f"{plugin_type}_options"
    opts_file = f"{plugin_type}_option_file"
    opts_cli_config = None
    if opts_arg in args or opts_file in args:
        if opts_arg in args:
            opts_argv = getattr(args, opts_arg)
            try:
                opts_cli_config = json.loads(opts_argv)
            except json.JSONDecodeError as e:
                logging.warning("Failed to parse JSON %s: %s", opts_arg, e.args[0])

        elif opts_file in args:
            file_arg = getattr(args, opts_file)
            if not os.path.isfile(file_arg):
                raise FileNotFoundError(f"Path provided is not a file: {opts_file}")
            with open(file_arg, encoding="utf-8") as f:
                options_json = f.read().strip()
            try:
                opts_cli_config = json.loads(options_json)
            except json.decoder.JSONDecodeError as e:
                logging.warning("Failed to parse JSON %s: %s", opts_file, {e.args[0]})
                raise e
    return opts_cli_config


def main(arguments=None) -> None:
    """Main entry point for garak runs invoked from the CLI"""
    import datetime

    from garak import __description__
    from garak import _config, _plugins
    from garak.exception import GarakException

    _config.transient.starttime = datetime.datetime.now()
    _config.transient.starttime_iso = _config.transient.starttime.isoformat()

    if arguments is None:
        arguments = []

    import garak.command as command
    import logging
    import re
    from colorama import Fore, Style

    log_filename = command.start_logging()
    _config.load_base_config()

    print(
        f"garak {__description__} v{_config.version} ( https://github.com/NVIDIA/garak ) at {_config.transient.starttime_iso}"
    )

    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m garak",
        description="LLM safety & security scanning tool",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
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
        default=_config.reporting.report_prefix,
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
        help="How many probe attempts to launch in parallel. Raise this for faster runs when using non-local models.",
    )
    parser.add_argument(
        "--skip_unknown",
        action="store_true",
        help="allow skip of unknown probes, detectors, or buffs",
    )

    ## RUN
    parser.add_argument(
        "--seed",
        "-s",
        type=int,
        default=_config.run.seed,
        help="random seed",
    )
    parser.add_argument(
        "--deprefix",
        action="store_false",
        help="remove the prompt from the front of generator output",
    )
    parser.add_argument(
        "--eval_threshold",
        type=float,
        default=_config.run.eval_threshold,
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
        "--config", type=str, default=None, help="YAML or JSON config file for this run"
    )
    parser.add_argument(
        "--resumable",
        type=str_to_bool,
        nargs="?",
        const=True,
        default=_config.run.resumable,
        help="Enable/disable resumable scans. Use --resumable true/false to override config (default: enabled)",
    )
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="Resume a previous run using the specified run ID (e.g., --resume garak-run-xxx)",
    )
    parser.add_argument(
        "--list_runs",
        action="store_true",
        help="List unfinished runs",
    )
    parser.add_argument(
        "--delete_run",
        type=str,
        default=None,
        help="Delete a run by ID",
    )
    parser.add_argument(
        "--resume_granularity",
        "--resume-granularity",
        type=str,
        choices=["probe", "attempt"],
        default=None,
        help="Resume granularity: 'probe' (skip completed probes) or 'attempt' (skip completed prompts). Overrides config file.",
    )

    ## PLUGINS
    # generators
    parser.add_argument(
        "--target_type",
        "-t",
        "--model_type",
        "-m",
        type=str,
        help="module and optionally also class of the generator, e.g. 'huggingface', or 'openai'",
    )
    parser.add_argument(
        "--target_name",
        "--model_name",
        "-n",
        type=str,
        default=None,
        help="name of the target, e.g. 'timdettmers/guanaco-33b-merged'",
    )
    # probes
    parser.add_argument(
        "--probes",
        "-p",
        type=str,
        default=_config.plugins.probe_spec,
        help="list of probe names to use, or 'all' for all (default).",
    )
    parser.add_argument(
        "--probe_tags",
        default=_config.run.probe_tags,
        type=str,
        help="only include probes with a tag that starts with this value (e.g. owasp:llm01)",
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
        "--buffs",
        "-b",
        type=str,
        default=_config.plugins.buff_spec,
        help="list of buffs to use. Default is none",
    )
    # file or json based config options
    plugin_types = sorted(
        zip([type.lower() for type in _plugins.PLUGIN_CLASSES], _plugins.PLUGIN_TYPES)
    )
    for plugin_type, _ in plugin_types:
        probe_args = parser.add_mutually_exclusive_group()
        probe_args.add_argument(
            f"--{plugin_type}_option_file",
            f"-{plugin_type[0].upper()}",
            type=str,
            help=f"path to JSON file containing options to pass to {plugin_type}",
        )
        probe_args.add_argument(
            f"--{plugin_type}_options",
            type=str,
            help=f"options to pass to {plugin_type}, formatted as a JSON dict",
        )
    ## REPORTING
    parser.add_argument(
        "--taxonomy",
        type=str,
        default=_config.reporting.taxonomy,
        help="specify a MISP top-level taxonomy to be used for grouping probes in reporting. e.g. 'avid-effect', 'owasp' ",
    )

    ## COMMANDS
    # items placed here also need to be listed in command_options below
    parser.add_argument(
        "--plugin_info",
        type=str,
        help="show info about one plugin; format as type.plugin.class, e.g. probes.lmrc.Profanity",
    )
    parser.add_argument(
        "--list_probes",
        action="store_true",
        help="list all available probes. Usage: combine with --probes/-p to filter for probes that will be activated based on a `probe_spec`, e.g. '--list_probes -p dan' to show only active 'dan' family probes.",
    )
    parser.add_argument(
        "--list_detectors",
        action="store_true",
        help="list available detectors. Usage: combine with --detectors/-d to filter for detectors that will be activated based on a `detector_spec`, e.g. '--list_detectors -d misleading.Invalid' to show only that detector.",
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
        "--list_config",
        action="store_true",
        help="print active config info (and don't scan)",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="store_true",
        help="print version info & exit",
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
        "--fix",
        action="store_true",
        help="Update provided configuration with fixer migrations; requires one of --config / --*_option_file, / --*_options",
    )

    ## EXPERIMENTAL FEATURES
    if _config.system.enable_experimental:
        # place parser argument defs for experimental features here
        parser.description = (
            str(parser.description) + " - EXPERIMENTAL FEATURES ENABLED"
        )

    logging.debug("args - raw argument string received: %s", arguments)

    args = parser.parse_args(arguments)
    logging.debug("args - full argparse: %s", args)

    for deprecated_model_option in {"-m", "--model_name", "--model_type"}.intersection(
        set(arguments)
    ):
        command.deprecation_notice(f"{deprecated_model_option} on CLI", "0.13.1.pre1")

    # load site config before loading CLI config
    _cli_config_supplied = args.config is not None
    prior_user_agents = _config.get_http_lib_agents()
    try:
        _config.load_config(run_config_filename=args.config)
    except FileNotFoundError as e:
        logging.exception(e)
        print(f"❌{e}")
        exit(1)

    # extract what was actually passed on CLI; use a masking argparser
    aux_parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
    # print('VARS', vars(args))
    # aux_parser is going to get sys.argv and so also needs the argument shortnames
    # will extract those from parser internals and use them to populate aux_parser
    arg_names = {}
    for action in parser._actions:
        raw_option_strings = [
            re.sub("^" + re.escape(parser.prefix_chars) + "+", "", a)
            for a in action.option_strings
        ]
        if "help" not in raw_option_strings:
            for raw_option_string in raw_option_strings:
                arg_names[raw_option_string] = action.option_strings

    for arg, val in vars(args).items():
        if arg == "verbose":
            # the 'verbose' flag is currently unique and retrieved from `args` directly
            continue
        if isinstance(val, bool):
            if val:
                aux_parser.add_argument(*arg_names[arg], action="store_true")
            else:
                aux_parser.add_argument(*arg_names[arg], action="store_false")
        else:
            aux_parser.add_argument(*arg_names[arg], type=type(val))

    # cli_args contains items specified on CLI; the rest not to be overridden
    cli_args, _ = aux_parser.parse_known_args(arguments)

    # exception: action=count. only verbose uses this, let's bubble it through
    cli_args.verbose = args.verbose

    # print('ARGS', args)
    # print('CLI_ARGS', cli_args)

    # also force command vars through to cli_args, even if false, to make command code easier
    for command_option in command_options:
        setattr(cli_args, command_option, getattr(args, command_option))

    logging.debug("args - cli_args&commands stored: %s", cli_args)

    del args
    args = cli_args
    # stash cli_args
    _config.transient.cli_args = cli_args
    _config.transient.args = args  # Also set args for command.py

    # Handle resume argument
    if hasattr(args, "resume") and args.resume:
        _config.transient.resume_run_id = args.resume

        # Load resumed state early to extract model_type and generator
        from garak import _plugins
        import garak.resumeservice as resumeservice

        resumeservice.load()
        state = resumeservice.get_state()
        if state:
            # Load model_type and generator from resumed state
            if "model_type" in state:
                _config.plugins.model_type = state["model_type"]
                _config.plugins.target_type = state[
                    "model_type"
                ]  # Set target_type for condition check
            if "model_name" in state:
                _config.plugins.model_name = state["model_name"]
            if "generator" in state:
                # Extract generator name from full class path
                generator_class = state["generator"]
                if "." in generator_class:
                    _config.plugins.model_type = generator_class.split(".")[-2]
                    _config.plugins.target_type = generator_class.split(".")[
                        -2
                    ]  # Set target_type for condition check
                    _config.plugins.model_name = generator_class.split(".")[-1]

            # Restore generator configuration
            if "generator_config" in state and state["generator_config"]:
                # Merge generator config into _config.plugins.generators
                for gen_family, gen_configs in state["generator_config"].items():
                    if not hasattr(_config.plugins, "generators"):
                        _config.plugins.generators = {}
                    if gen_family not in _config.plugins.generators:
                        _config.plugins.generators[gen_family] = {}
                    for gen_name, gen_params in gen_configs.items():
                        _config.plugins.generators[gen_family][gen_name] = gen_params

            # Restore run configuration parameters
            if "run_generations" in state:
                _config.run.generations = state["run_generations"]
            if "run_deprefix" in state:
                _config.run.deprefix = state["run_deprefix"]

            # Restore reporting configuration parameters
            if "reporting_group_aggregation_function" in state:
                _config.reporting.group_aggregation_function = state[
                    "reporting_group_aggregation_function"
                ]

    # save args info into config
    # need to know their type: plugin, system, or run
    # ignore params not listed here
    # - sorry, this means duping stuff, i know. maybe better argparse setup will help
    ignored_params = []
    for param, value in vars(args).items():
        if param in _config.system_params:
            setattr(_config.system, param, value)
        elif param in _config.run_params:
            setattr(_config.run, param, value)
        elif param in _config.plugins_params:
            setattr(_config.plugins, param, value)
        elif param in _config.reporting_params:
            setattr(_config.reporting, param, value)
        else:
            ignored_params.append((param, value))
    logging.debug("non-config params: %s", ignored_params)

    # put plugin spec into the _spec config value, if set at cli
    if "probes" in args:
        _config.plugins.probe_spec = args.probes
    if "detectors" in args:
        _config.plugins.detector_spec = args.detectors
    if "buffs" in args:
        _config.plugins.buff_spec = args.buffs

    # base config complete

    # post-config validation
    def worker_count_validation(workers):
        iworkers = int(workers)
        if iworkers <= 0:
            raise ValueError(
                "Need a number > 0 for --parallel_attempts, --parallel_requests"
            )
        if iworkers > _config.system.max_workers:
            raise ValueError(
                "Parallel worker count capped at %s (config.system.max_workers), try a lower value for --parallel_attempts or --parallel_requests"
                % _config.system.max_workers
            )
        return iworkers

    try:
        if _config.system.parallel_attempts is not False:
            _config.system.parallel_attempts = worker_count_validation(
                _config.system.parallel_attempts
            )

        if _config.system.parallel_requests is not False:
            _config.system.parallel_requests = worker_count_validation(
                _config.system.parallel_requests
            )
    except ValueError as e:
        logging.exception(e)
        print(e)
        exit(1)  # exit non zero indicated parsing error

    if hasattr(_config.run, "seed") and isinstance(_config.run.seed, int):
        import random

        random.seed(
            _config.run.seed
        )  # setting seed persists across re-imports of random

    # startup
    import sys
    import json

    import garak.evaluators

    try:
        has_config_file_or_json = False
        # do a special thing for CLI probe options, generator options
        for plugin_type, plugin_plural in plugin_types:
            opts_cli_config = parse_cli_plugin_config(plugin_type, args)
            if opts_cli_config is not None:
                has_config_file_or_json = True
                config_plugin_type = getattr(_config.plugins, plugin_plural)

                config_plugin_type = _config._combine_into(
                    opts_cli_config, config_plugin_type
                )

        # process commands
        if args.interactive:
            from garak.interactive import interactive_mode

            try:
                command.start_run()  # start run to track actions
                interactive_mode()
            except Exception as e:
                logging.error(e)
                print(e)
                sys.exit(1)
            finally:
                command.end_run()

        # Handle resume-related commands
        if hasattr(args, "list_runs") and args.list_runs:
            from garak import resumeservice
            from datetime import datetime

            runs = resumeservice.list_runs()
            if not runs:
                print("\n📋 No unfinished runs found.")
                print(
                    "\nStart a new resumable scan with: garak --resumable [options]\n"
                )
            else:
                print("\n📋 Resumable Runs\n")

                # Print header
                print(
                    f"{'#':<4} {'Run ID':<38} {'Started':<20} {'Progress':<12} {'%':<6}"
                )
                print("-" * 82)

                for idx, run in enumerate(runs, 1):
                    # Calculate percentage
                    percentage = (
                        (run["progress"] / run["total"] * 100)
                        if run["total"] > 0
                        else 0
                    )

                    # Format the timestamp more readably
                    try:
                        dt = datetime.fromisoformat(run["start_time"])
                        formatted_time = dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        formatted_time = run["start_time"][:16]

                    # Progress format
                    progress_str = f"{run['progress']}/{run['total']}"

                    print(
                        f"{idx:<4} {run['run_id']:<38} {formatted_time:<20} {progress_str:<12} {percentage:>5.1f}%"
                    )

                print("-" * 82)
                print(f"\nTotal: {len(runs)} unfinished run(s)")
                print("\nTo resume: garak --resume <run_id>")
                print("To delete: garak --delete_run <run_id>\n")
            return

        if hasattr(args, "delete_run") and args.delete_run:
            from garak import resumeservice

            try:
                resumeservice.delete_run(args.delete_run)
                print(f"✅ Deleted run: {args.delete_run}")
            except Exception as e:
                print(f"❌ Failed to delete run: {e}")
                import sys

                sys.exit(1)
            return

        if args.version:
            pass

        elif args.plugin_info:
            command.plugin_info(args.plugin_info)

        elif args.list_probes:
            selected_probes = None
            probe_spec = getattr(args, "probes", None)
            if probe_spec and probe_spec.lower() not in ("", "auto", "all", "*"):
                selected_probes, _ = _config.parse_plugin_spec(probe_spec, "probes")
            command.print_probes(selected_probes)

        elif args.list_detectors:
            selected_detectors = None
            detector_spec = getattr(args, "detectors", None)
            if detector_spec and detector_spec.lower() not in ("", "auto", "all", "*"):
                selected_detectors, _ = _config.parse_plugin_spec(
                    detector_spec, "detectors"
                )
            command.print_detectors(selected_detectors)

        elif args.list_buffs:
            command.print_buffs()

        elif args.list_generators:
            command.print_generators()

        elif args.list_config:
            print("cli args:\n ", args)
            command.list_config()

        elif args.fix:
            from garak.resources import fixer
            import json
            import yaml

            # process all possible configuration entries
            # should this restrict the config updates to a single fixable value?
            # for example allowed commands:
            # --fix --config filename.yaml
            # --fix --generator_option_file filename.json
            # --fix --generator_options json
            #
            # disallowed commands:
            # --fix --config filename.yaml --generator_option_file filename.json
            # --fix --generator_option_file filename.json --probe_option_file filename.json
            #
            # already unsupported as only one is held:
            # --fix --generator_option_file filename.json --generator_options json_data
            #
            # How should this handle garak.site.yaml? Only if --fix was provided and no other options offered?
            # For now process all files registered a part of the config
            has_changes = False
            if has_config_file_or_json:
                for plugin_type, plugin_plural in plugin_types:
                    # cli plugins options stub out only a "plugins" sub key
                    plugin_cli_config = parse_cli_plugin_config(plugin_type, args)
                    if plugin_cli_config is not None:
                        cli_config = {
                            "plugins": {f"{plugin_plural}": plugin_cli_config}
                        }
                        migrated_config = fixer.migrate(cli_config)
                        if cli_config != migrated_config:
                            has_changes = True
                            msg = f"Updated '{plugin_type}' configuration: \n"
                            msg += json.dumps(
                                migrated_config["plugins"][plugin_plural], indent=2
                            )  # pretty print the config in json
                            print(msg)
            else:
                # check if garak.site.yaml needs to be fixed up?
                for filename in _config.config_files:
                    with open(filename, encoding="UTF-8") as file:
                        cli_config = yaml.safe_load(file)
                        migrated_config = fixer.migrate(cli_config)
                        if cli_config != migrated_config:
                            has_changes = True
                            msg = f"Updated {filename}: \n"
                            msg += yaml.dump(migrated_config)
                            print(msg)
            # should this add support for --*_spec entries passed on cli?
            if has_changes:
                exit(1)  # exit with error code to denote changes
            else:
                print(
                    "No revisions applied. Please verify options provided for `--fix`"
                )
        elif args.report:
            from garak.report import Report

            report_location = args.report
            print(f"📜 Converting garak reports {report_location}")
            report = Report(args.report).load().get_evaluations()
            report.export()
            print(f"📜 AVID reports generated at {report.write_location}")

        # model is specified, we're doing something
        elif _config.plugins.target_type:

            print(f"📜 logging to {log_filename}")

            conf_root = _config.plugins.generators
            for part in _config.plugins.target_type.split("."):
                if not part in conf_root:
                    conf_root[part] = {}
                conf_root = conf_root[part]
            if _config.plugins.target_name:
                # if passed generator options and config files are already loaded
                # cli provided name overrides config from file
                conf_root["name"] = _config.plugins.target_name

            # Can this check be deferred to the generator instantiation?
            if (
                _config.plugins.target_type
                in ("openai", "replicate", "ggml", "huggingface", "litellm")
                and not _config.plugins.target_name
            ):
                message = f"⚠️  Model type '{_config.plugins.target_type}' also needs a model name\n You can set one with e.g. --target_name \"billwurtz/gpt-1.0\""
                logging.error(message)
                raise ValueError(message)

            # RESUME SUPPORT: Restore report paths and override probe spec with probes from resumed run
            from garak import resumeservice

            if resumeservice.enabled():
                resumed_state = resumeservice.get_state()
                if resumed_state:
                    # Restore report directory and prefix from resumed state
                    if "report_dir" in resumed_state:
                        _config.reporting.report_dir = resumed_state["report_dir"]
                        logging.info(
                            f"Restored report_dir from state: {resumed_state['report_dir']}"
                        )
                    if "report_prefix" in resumed_state:
                        _config.reporting.report_prefix = resumed_state["report_prefix"]
                        logging.info(
                            f"Restored report_prefix from state: {resumed_state['report_prefix']}"
                        )

                    # Use the original run_id to maintain report filename consistency
                    if "run_id" in resumed_state:
                        _config.transient.run_id = resumed_state["run_id"]
                        logging.info(f"Restored run_id from state: {resumed_state['run_id']}")

                    # Override probe spec with probes from resumed run
                    if "probenames" in resumed_state:
                        resumed_probes = resumed_state["probenames"]
                        # Strip "probes." prefix if present for parse_plugin_spec compatibility
                        resumed_probes_clean = [
                            p.replace("probes.", "") for p in resumed_probes
                        ]
                        # Convert probe list to comma-separated spec
                        _config.plugins.probe_spec = ",".join(resumed_probes_clean)
                        logging.info(
                            f"Resuming run with probes from state: {resumed_probes}"
                        )
                        print(
                            f"🔄 Using probes from resumed run: {', '.join(resumed_probes_clean)}"
                        )

            parsable_specs = ["probe", "detector", "buff"]
            parsed_specs = {}
            for spec_type in parsable_specs:
                spec_namespace = f"{spec_type}s"
                config_spec = getattr(_config.plugins, f"{spec_type}_spec", "")
                config_tags = getattr(_config.run, f"{spec_type}_tags", "")
                names, rejected = _config.parse_plugin_spec(
                    config_spec, spec_namespace, config_tags
                )
                parsed_specs[spec_type] = names
                if rejected is not None and len(rejected) > 0:
                    if hasattr(args, "skip_unknown"):  # attribute only set when True
                        header = f"Unknown {spec_namespace}:"
                        skip_msg = Fore.LIGHTYELLOW_EX + "SKIP" + Style.RESET_ALL
                        msg = f"{Fore.LIGHTYELLOW_EX}{header}\n" + "\n".join(
                            [f"{skip_msg} {spec}" for spec in rejected]
                        )
                        logging.warning(f"{header} " + ",".join(rejected))
                        print(msg)
                    else:
                        msg_list = ",".join(rejected)
                        raise ValueError(f"❌Unknown {spec_namespace}❌: {msg_list}")

            evaluator = garak.evaluators.ThresholdEvaluator(_config.run.eval_threshold)

            from garak import _plugins

            generator = _plugins.load_plugin(
                f"generators.{_config.plugins.target_type}", config_root=_config
            )

            if (
                not _cli_config_supplied
                and generator.parallel_capable
                and _config.system.parallel_attempts is False
            ):
                command.hint(
                    f"This run can be sped up 🥳 Generator '{generator.fullname}' supports parallelism! Consider using `--parallel_attempts 16` (or more) to greatly accelerate your run. 🐌",
                    logging=logging,
                )

            # RESUME SUPPORT: Set up report file before start_run()
            import uuid
            import os
            from pathlib import Path

            def parse_existing_report_metadata(report_path):
                """Parse existing report to extract original run_id and start_time.

                Args:
                    report_path: Path to existing report.jsonl file

                Returns:
                    Tuple of (run_id, start_time) or (None, None) if not found
                """
                if not os.path.exists(report_path):
                    return None, None

                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if not line.strip():
                                continue
                            entry = json.loads(line.strip())
                            if entry.get("entry_type") == "init":
                                return entry.get("run"), entry.get("start_time")
                except Exception as e:
                    logging.warning(f"Could not parse existing report metadata: {e}")

                return None, None

            # Set run_id first (needed for report filename)
            if not hasattr(_config.transient, "run_id") or not _config.transient.run_id:
                _config.transient.run_id = str(uuid.uuid4())

            # Check if resuming
            is_resuming = (
                hasattr(_config.transient, "resume_run_id")
                and _config.transient.resume_run_id
            )
            original_start_time = None

            if is_resuming:
                # The run_id, report_dir, and report_prefix should already be restored by earlier code
                # NOW construct report path using the loaded run_id
                report_dir = _config.transient.data_dir / _config.reporting.report_dir
                report_prefix = (
                    _config.reporting.report_prefix
                    or f"garak.{_config.transient.run_id}"
                )
                expected_report_path = str(report_dir / f"{report_prefix}.report.jsonl")

                # Parse existing report to verify and get original start_time
                parsed_run_id, original_start_time = parse_existing_report_metadata(
                    expected_report_path
                )

                if original_start_time:
                    logging.info(
                        f"Preserving original start_time: {original_start_time}"
                    )
                    _config.transient.original_start_time = original_start_time
                    # CRITICAL: Update starttime_iso to use the ORIGINAL timestamp, not current time
                    _config.transient.starttime_iso = original_start_time
                else:
                    logging.warning(
                        "Could not find original start_time in existing report"
                    )

            # Set up report directory
            report_dir = _config.transient.data_dir / _config.reporting.report_dir
            report_dir.mkdir(parents=True, exist_ok=True)

            # Set up report filename
            report_prefix = (
                _config.reporting.report_prefix or f"garak.{_config.transient.run_id}"
            )
            _config.transient.report_filename = str(
                report_dir / f"{report_prefix}.report.jsonl"
            )

            # Set file mode - append if resuming and file exists, otherwise write
            file_mode = (
                "a"
                if (is_resuming and os.path.exists(_config.transient.report_filename))
                else "w"
            )

            # Open report file
            _config.transient.reportfile = open(
                _config.transient.report_filename,
                file_mode,
                buffering=1,
                encoding="utf-8",
            )

            # Open hitlog file if needed
            hitlog_filename = str(report_dir / f"{report_prefix}.hitlog.jsonl")
            hitlog_file_mode = (
                "a" if (is_resuming and os.path.exists(hitlog_filename)) else "w"
            )
            _config.transient.hitlogfile = open(
                hitlog_filename, hitlog_file_mode, buffering=1, encoding="utf-8"
            )

            # Write setup and init entries to report (only if not resuming)
            if not is_resuming:
                # Write setup entry first
                setup_dict = {"entry_type": "start_run setup"}
                # Fields to exclude from run_params list only (not from actual config values)
                exclude_from_params_list = {"resumable", "resume_granularity"}

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
                        # Filter resume-specific params from run_params list only
                        if k == "run_params":
                            filtered_params = [
                                p for p in v if p not in exclude_from_params_list
                            ]
                            setup_dict[f"_config.{k}"] = filtered_params
                        else:
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

                _config.transient.reportfile.write(
                    json.dumps(setup_dict, ensure_ascii=False) + "\n"
                )

                # Write init entry
                init_entry = {
                    "entry_type": "init",
                    "garak_version": _config.version,
                    "start_time": _config.transient.starttime_iso,
                    "run": _config.transient.run_id,
                }
                # Add resume capability metadata if enabled
                if hasattr(_config.run, "resumable") and _config.run.resumable:
                    init_entry["resume_enabled"] = True
                    if hasattr(_config.run, "resume_granularity"):
                        init_entry["resume_granularity"] = (
                            _config.run.resume_granularity
                        )
                _config.transient.reportfile.write(
                    json.dumps(init_entry, ensure_ascii=False) + "\n"
                )

            command.start_run()  # start the run now that all config validation is complete
            print(f"📜 reporting to {_config.transient.report_filename}")

            if parsed_specs["detector"] == []:
                command.probewise_run(
                    generator, parsed_specs["probe"], evaluator, parsed_specs["buff"]
                )
            else:
                command.pxd_run(
                    generator,
                    parsed_specs["probe"],
                    parsed_specs["detector"],
                    evaluator,
                    parsed_specs["buff"],
                )

            command.end_run()
        else:
            print("nothing to do 🤷  try --help")
            if _config.plugins.target_name and not _config.plugins.target_type:
                print(
                    "💡 try setting --target_type (--target_name is currently set but not --target_type)"
                )
            logging.info("nothing to do 🤷")
    except KeyboardInterrupt as e:
        msg = "User cancel received, terminating all runs"
        logging.exception(e)
        logging.info(msg)
        print(msg)
    except (ValueError, GarakException) as e:
        logging.exception(e)
        print(e)

    _config.set_http_lib_agents(prior_user_agents)
