CLI reference for garak
=======================

::

  garak LLM vulnerability scanner v0.14.0.pre1 ( https://github.com/NVIDIA/garak ) at 2026-01-12T10:55:00.848157
  usage: python -m garak [-h] [--verbose] [--report_prefix REPORT_PREFIX]
                         [--narrow_output]
                         [--parallel_requests PARALLEL_REQUESTS]
                         [--parallel_attempts PARALLEL_ATTEMPTS]
                         [--skip_unknown] [--seed SEED] [--deprefix]
                         [--eval_threshold EVAL_THRESHOLD]
                         [--generations GENERATIONS] [--config CONFIG]
                         [--target_type TARGET_TYPE] [--target_name TARGET_NAME]
                         [--probes PROBES] [--probe_tags PROBE_TAGS]
                         [--detectors DETECTORS] [--extended_detectors]
                         [--buffs BUFFS]
                         [--buff_option_file BUFF_OPTION_FILE | --buff_options BUFF_OPTIONS]
                         [--detector_option_file DETECTOR_OPTION_FILE | --detector_options DETECTOR_OPTIONS]
                         [--generator_option_file GENERATOR_OPTION_FILE | --generator_options GENERATOR_OPTIONS]
                         [--harness_option_file HARNESS_OPTION_FILE | --harness_options HARNESS_OPTIONS]
                         [--probe_option_file PROBE_OPTION_FILE | --probe_options PROBE_OPTIONS]
                         [--taxonomy TAXONOMY] [--plugin_info PLUGIN_INFO]
                         [--list_probes] [--list_detectors] [--list_generators]
                         [--list_buffs] [--list_config] [--version]
                         [--report REPORT] [--interactive] [--fix]
  
  LLM safety & security scanning tool
  
  options:
    -h, --help            show this help message and exit
    --verbose, -v         add one or more times to increase verbosity of output
                          during runtime
    --report_prefix REPORT_PREFIX
                          Specify an optional prefix for the report and hit logs
    --narrow_output       give narrow CLI output
    --parallel_requests PARALLEL_REQUESTS
                          How many generator requests to launch in parallel for
                          a given prompt. Ignored for models that support
                          multiple generations per call.
    --parallel_attempts PARALLEL_ATTEMPTS
                          How many probe attempts to launch in parallel. Raise
                          this for faster runs when using non-local models.
    --skip_unknown        allow skip of unknown probes, detectors, or buffs
    --seed SEED, -s SEED  random seed
    --deprefix            remove the prompt from the front of generator output
    --eval_threshold EVAL_THRESHOLD
                          minimum threshold for a successful hit
    --generations GENERATIONS, -g GENERATIONS
                          number of generations per prompt
    --config CONFIG       YAML or JSON config file for this run
    --target_type TARGET_TYPE, -t TARGET_TYPE, --model_type TARGET_TYPE, -m TARGET_TYPE
                          module and optionally also class of the generator,
                          e.g. 'huggingface', or 'openai'
    --target_name TARGET_NAME, --model_name TARGET_NAME, -n TARGET_NAME
                          name of the target, e.g.
                          'timdettmers/guanaco-33b-merged'
    --probes PROBES, -p PROBES
                          list of probe names to use, or 'all' for all
                          (default).
    --probe_tags PROBE_TAGS
                          only include probes with a tag that starts with this
                          value (e.g. owasp:llm01)
    --detectors DETECTORS, -d DETECTORS
                          list of detectors to use, or 'all' for all. Default is
                          to use the probe's suggestion.
    --extended_detectors  If detectors aren't specified on the command line,
                          should we run all detectors? (default is just the
                          primary detector, if given, else everything)
    --buffs BUFFS, -b BUFFS
                          list of buffs to use. Default is none
    --buff_option_file BUFF_OPTION_FILE, -B BUFF_OPTION_FILE
                          path to JSON file containing options to pass to buff
    --buff_options BUFF_OPTIONS
                          options to pass to buff, formatted as a JSON dict
    --detector_option_file DETECTOR_OPTION_FILE, -D DETECTOR_OPTION_FILE
                          path to JSON file containing options to pass to
                          detector
    --detector_options DETECTOR_OPTIONS
                          options to pass to detector, formatted as a JSON dict
    --generator_option_file GENERATOR_OPTION_FILE, -G GENERATOR_OPTION_FILE
                          path to JSON file containing options to pass to
                          generator
    --generator_options GENERATOR_OPTIONS
                          options to pass to generator, formatted as a JSON dict
    --harness_option_file HARNESS_OPTION_FILE, -H HARNESS_OPTION_FILE
                          path to JSON file containing options to pass to
                          harness
    --harness_options HARNESS_OPTIONS
                          options to pass to harness, formatted as a JSON dict
    --probe_option_file PROBE_OPTION_FILE, -P PROBE_OPTION_FILE
                          path to JSON file containing options to pass to probe
    --probe_options PROBE_OPTIONS
                          options to pass to probe, formatted as a JSON dict
    --taxonomy TAXONOMY   specify a MISP top-level taxonomy to be used for
                          grouping probes in reporting. e.g. 'avid-effect',
                          'owasp'
    --plugin_info PLUGIN_INFO
                          show info about one plugin; format as
                          type.plugin.class, e.g. probes.lmrc.Profanity
    --list_probes         list all available probes. Usage: combine with
                          --probes/-p to filter for probes that will be
                          activated based on a `probe_spec`, e.g. '--list_probes
                          -p dan' to show only active 'dan' family probes.
    --list_detectors      list available detectors. Usage: combine with
                          --detectors/-d to filter for detectors that will be
                          activated based on a `detector_spec`, e.g. '--
                          list_detectors -d misleading.Invalid' to show only
                          that detector.
    --list_generators     list available generation model interfaces
    --list_buffs          list available buffs/fuzzes
    --list_config         print active config info (and don't scan)
    --version, -V         print version info & exit
    --report REPORT, -r REPORT
                          process garak report into a list of AVID reports
    --interactive, -I     Enter interactive probing mode
    --fix                 Update provided configuration with fixer migrations;
                          requires one of --config / --*_option_file, /
                          --*_options
  
  See https://github.com/NVIDIA/garak
