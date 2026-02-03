"""garak global config"""

# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# plugin code < base config < site config < run config < cli params

# logging should be set up before config is loaded

import platform
from collections import defaultdict
from dataclasses import dataclass
import importlib
import json
import logging
import os
import stat
import pathlib
from typing import List
import yaml
from xdg_base_dirs import (
    xdg_cache_home,
    xdg_config_home,
    xdg_data_home,
)

DICT_CONFIG_AFTER_LOAD = False
DEPRECATED_CONFIG_PATHS = {
    "plugins.model_type": "0.13.1.pre1",
    "plugins.model_name": "0.13.1.pre1",
}

from garak import __version__ as version

system_params = (
    "verbose narrow_output parallel_requests parallel_attempts skip_unknown".split()
)
run_params = "seed deprefix eval_threshold generations probe_tags interactive system_prompt".split()
plugins_params = "target_type target_name extended_detectors".split()
reporting_params = "taxonomy report_prefix".split()
project_dir_name = "garak"


loaded = False


@dataclass
class GarakSubConfig:
    pass


@dataclass
class BuffManager:
    """class to store instantiated buffs"""

    buffs = []


@dataclass
class TransientConfig(GarakSubConfig):
    """Object to hold transient global config items not set externally"""

    log_filename = None
    report_filename = None
    reportfile = None
    hitlogfile = None
    args = None  # only access this when determining what was passed on CLI
    run_id = None
    package_dir = pathlib.Path(__file__).parents[0]
    config_dir = xdg_config_home() / project_dir_name
    data_dir = xdg_data_home() / project_dir_name
    cache_dir = xdg_cache_home() / project_dir_name
    starttime = None
    starttime_iso = None

    # initialize the user home and cache paths if they do not exist
    config_dir.mkdir(mode=0o740, parents=True, exist_ok=True)
    data_dir.mkdir(mode=0o740, parents=True, exist_ok=True)
    cache_dir.mkdir(mode=0o740, parents=True, exist_ok=True)


transient = TransientConfig()

system = GarakSubConfig()
run = GarakSubConfig()
plugins = GarakSubConfig()
reporting = GarakSubConfig()


def _lock_config_as_dict():
    global plugins
    for plugin_type in ("probes", "generators", "buffs", "detectors", "harnesses"):
        setattr(plugins, plugin_type, _crystallise(getattr(plugins, plugin_type)))


def _crystallise(d):
    for k in d.keys():
        if isinstance(d[k], defaultdict):
            d[k] = _crystallise(d[k])
    return dict(d)


def _nested_dict():
    return defaultdict(nested_dict)


nested_dict = _nested_dict

plugins.probes = nested_dict()
plugins.generators = nested_dict()
plugins.detectors = nested_dict()
plugins.buffs = nested_dict()
plugins.harnesses = nested_dict()
reporting.taxonomy = None  # set here to enable report_digest to be called directly

buffmanager = BuffManager()

config_files = []

# this is so popular, let's set a default. what other defaults are worth setting? what's the policy?
run.seed = None
run.soft_probe_prompt_cap = 64
run.target_lang = "en"
run.langproviders = []

# placeholder
# generator, probe, detector, buff = {}, {}, {}, {}


def _key_exists(d: dict, key: str) -> bool:
    # Check for the presence of a key in a nested dict.
    if not isinstance(d, dict) and not isinstance(d, list):
        return False
    if isinstance(d, list):
        return any([_key_exists(item, key) for item in d])
    if isinstance(d, dict) and key in d.keys():
        return True
    else:
        return any([_key_exists(val, key) for val in d.values()])


def _set_settings(config_obj, settings_obj: dict):
    for k, v in settings_obj.items():
        setattr(config_obj, k, v)
    return config_obj


def _combine_into(d: dict, combined: dict) -> dict:
    if d is None:
        return combined
    for k, v in d.items():
        if isinstance(v, dict):
            _combine_into(v, combined.setdefault(k, nested_dict()))
        else:
            combined[k] = v
    return combined


def _load_config_files(settings_filenames) -> dict:
    global config_files
    config_files += settings_filenames
    config = nested_dict()
    for settings_filename in settings_filenames:
        with open(settings_filename, encoding="utf-8") as settings_file:
            try:
                settings = json.load(settings_file)
            except json.JSONDecodeError:
                settings_file.seek(0)
                try:
                    settings = yaml.safe_load(settings_file)
                except yaml.YAMLError as e:
                    message = f"Failed to parse config file {settings_filename} as JSON or YAML: {e}"
                    logging.error(message)
                    raise ValueError(message) from e
            if settings is not None:
                if _key_exists(settings, "api_key"):
                    if platform.system() == "Windows":
                        msg = (
                            f"A possibly secret value (`api_key`) was detected in {settings_filename}. "
                            f"We recommend removing potentially sensitive values from config files or "
                            f"ensuring the file is readable only by you."
                        )
                        logging.warning(msg)
                        print(f"⚠️  {msg}")
                    else:
                        logging.info(
                            f"API key found in {settings_filename}. Checking readability..."
                        )
                        res = os.stat(settings_filename)
                        if res.st_mode & stat.S_IROTH or res.st_mode & stat.S_IRGRP:
                            msg = (
                                f"A possibly secret value (`api_key`) was detected in {settings_filename}, "
                                f"which is readable by users other than yourself. "
                                f"Consider changing permissions on this file to only be readable by you."
                            )
                            logging.warning(msg)
                            print(f"⚠️  {msg}")
                config = _combine_into(settings, config)

    if "model_type" in config["plugins"]:
        import garak.command

        garak.command.deprecation_notice("config plugins.model_type", "0.13.1.pre1")
        if "target_type" in config["plugins"]:
            logging.info(
                "both target_type and model_type specified, ignoring model_type"
            )
        else:
            config["plugins"]["target_type"] = config["plugins"]["model_type"]
        del config["plugins"]["model_type"]

    if "model_name" in config["plugins"]:
        import garak.command

        garak.command.deprecation_notice("config plugins.model_name", "0.13.1.pre1")
        if "target_name" in config["plugins"]:
            logging.info(
                "both target_name and model_name specified, ignoring model_name"
            )
        else:
            config["plugins"]["target_name"] = config["plugins"]["model_name"]
        del config["plugins"]["model_name"]

    return config


def _store_config(settings_files) -> None:
    global system, run, plugins, reporting, version
    settings = _load_config_files(settings_files)
    system = _set_settings(system, settings["system"])
    run = _set_settings(run, settings["run"])
    run.user_agent = run.user_agent.replace("{version}", version)
    plugins = _set_settings(plugins, settings["plugins"])
    reporting = _set_settings(reporting, settings["reporting"])


# not my favourite solution in this module, but if
# _config.set_http_lib_agents() to be predicated on a param instead of
# a _config.run value (i.e. user_agent) - which it needs to be if it can be
# used when the values are popped back to originals - then a separate way
# of passing the UA string to _garak_user_agent() needs to exist, outside of
# _config.run.user_agent
REQUESTS_AGENT = ""


def _garak_user_agent(dummy=None):
    return str(REQUESTS_AGENT)


def set_all_http_lib_agents(agent_string):
    set_http_lib_agents(
        {"requests": agent_string, "httpx": agent_string, "aiohttp": agent_string}
    )


def set_http_lib_agents(agent_strings: dict):

    global REQUESTS_AGENT

    if "requests" in agent_strings:
        from requests import utils

        REQUESTS_AGENT = agent_strings["requests"]
        utils.default_user_agent = _garak_user_agent
    if "httpx" in agent_strings:
        import httpx

        httpx._client.USER_AGENT = agent_strings["httpx"]
    if "aiohttp" in agent_strings:
        import aiohttp

        aiohttp.client_reqrep.SERVER_SOFTWARE = agent_strings["aiohttp"]


def get_http_lib_agents():
    from requests import utils
    import httpx
    import aiohttp

    agent_strings = {}
    agent_strings["requests"] = utils.default_user_agent
    agent_strings["httpx"] = httpx._client.USER_AGENT
    agent_strings["aiohttp"] = aiohttp.client_reqrep.SERVER_SOFTWARE

    return agent_strings


def load_base_config() -> None:
    global loaded
    settings_files = [str(transient.package_dir / "resources" / "garak.core.yaml")]
    logging.debug("Loading configs from: %s", ",".join(settings_files))
    _store_config(settings_files=settings_files)
    loaded = True


def load_config(
    site_config_filename="garak.site.yaml", run_config_filename=None
) -> None:
    # would be good to bubble up things from run_config, e.g. generator, probe(s), detector(s)
    # and then not have cli be upset when these are not given as cli params
    global loaded

    settings_files = [str(transient.package_dir / "resources" / "garak.core.yaml")]

    if site_config_filename == "garak.site.yaml":
        site_config_json = str(transient.config_dir / "garak.site.json")
        site_config_yaml = str(transient.config_dir / "garak.site.yaml")
        site_config_yml = str(transient.config_dir / "garak.site.yml")

        has_json = os.path.isfile(site_config_json)
        has_yaml = os.path.isfile(site_config_yaml)
        has_yml = os.path.isfile(site_config_yml)

        if sum([has_json, has_yaml, has_yml]) > 1:
            message = "Multiple site config files found (garak.site.json, garak.site.yaml, garak.site.yml). Please use only one site config format."
            logging.error(message)
            raise ValueError(message)
        elif has_json:
            settings_files.append(site_config_json)
        elif has_yaml:
            settings_files.append(site_config_yaml)
        elif has_yml:
            settings_files.append(site_config_yml)
        else:
            logging.debug(
                "no site config found at: %s, %s, or %s",
                site_config_json,
                site_config_yaml,
                site_config_yml,
            )
    else:
        fq_site_config_filename = str(transient.config_dir / site_config_filename)
        if os.path.isfile(fq_site_config_filename):
            settings_files.append(fq_site_config_filename)
        else:
            logging.debug("no site config found at: %s", fq_site_config_filename)

    if run_config_filename is not None:
        # If file exists as-is, use it
        if os.path.isfile(run_config_filename):
            settings_files.append(run_config_filename)
        # If explicit extension, check bundled
        elif run_config_filename.lower().endswith((".json", ".yaml", ".yml")):
            bundled = str(transient.package_dir / "configs" / run_config_filename)
            if os.path.isfile(bundled):
                settings_files.append(bundled)
            else:
                message = f"run config not found: {run_config_filename}"
                logging.error(message)
                raise FileNotFoundError(message)
        # Extension-less: JSON-only, YAML needs explicit .yaml/.yml
        else:
            json_path = run_config_filename + ".json"
            yaml_path = run_config_filename + ".yaml"
            yml_path = run_config_filename + ".yml"
            json_bundled = str(
                transient.package_dir / "configs" / (run_config_filename + ".json")
            )
            yaml_bundled = str(
                transient.package_dir / "configs" / (run_config_filename + ".yaml")
            )
            yml_bundled = str(
                transient.package_dir / "configs" / (run_config_filename + ".yml")
            )

            has_json = os.path.isfile(json_path)
            has_yaml = os.path.isfile(yaml_path)
            has_yml = os.path.isfile(yml_path)
            has_json_bundled = os.path.isfile(json_bundled)
            has_yaml_bundled = os.path.isfile(yaml_bundled)
            has_yml_bundled = os.path.isfile(yml_bundled)

            # Direct path: JSON-only, warn if both exist
            if has_json or has_yaml or has_yml:
                if has_json and (has_yaml or has_yml):
                    yaml_ext = ".yaml" if has_yaml else ".yml"
                    logging.warning(
                        f"Both {run_config_filename}.json and {yaml_ext} found. Using .json"
                    )
                if has_json:
                    settings_files.append(json_path)
                else:
                    yaml_ext = ".yaml" if has_yaml else ".yml"
                    message = f"Found {run_config_filename}{yaml_ext} but YAML needs explicit .yaml/.yml extension"
                    logging.error(message)
                    raise FileNotFoundError(message)
            elif has_json_bundled:
                settings_files.append(json_bundled)
            elif has_yaml_bundled or has_yml_bundled:
                yaml_ext = ".yaml" if has_yaml_bundled else ".yml"
                message = f"Found {run_config_filename}{yaml_ext} but YAML needs explicit .yaml/.yml extension"
                logging.error(message)
                raise FileNotFoundError(message)
            else:
                message = f"run config not found: {run_config_filename}"
                logging.error(message)
                raise FileNotFoundError(message)

    logging.debug("Loading configs from: %s", ",".join(settings_files))
    _store_config(settings_files=settings_files)

    if DICT_CONFIG_AFTER_LOAD:
        _lock_config_as_dict()
    loaded = True


def parse_plugin_spec(
    spec: str, category: str, probe_tag_filter: str = ""
) -> tuple[List[str], List[str]]:
    from garak._plugins import enumerate_plugins

    if spec is None or spec.lower() in ("", "auto", "none"):
        return [], []
    unknown_plugins = []
    if spec.lower() in ("all", "*"):
        plugin_names = [
            name
            for name, active in enumerate_plugins(category=category)
            if active is True
        ]
    else:
        plugin_names = []
        for clause in spec.split(","):
            if clause.count(".") < 1:
                found_plugins = [
                    p
                    for p, a in enumerate_plugins(category=category)
                    if p.startswith(f"{category}.{clause}.") and a is True
                ]
                if len(found_plugins) > 0:
                    plugin_names += found_plugins
                else:
                    unknown_plugins += [clause]
            else:
                # validate the class exists
                found_plugins = [
                    p
                    for p, a in enumerate_plugins(category=category)
                    if p == f"{category}.{clause}"
                ]
                if len(found_plugins) > 0:
                    plugin_names += found_plugins
                else:
                    unknown_plugins += [clause]

    if probe_tag_filter is not None and len(probe_tag_filter) > 1:
        plugins_to_skip = []
        for plugin_name in plugin_names:
            plugin_module_name = ".".join(plugin_name.split(".")[:-1])
            plugin_class_name = plugin_name.split(".")[-1]
            m = importlib.import_module(f"garak.{plugin_module_name}")
            c = getattr(m, plugin_class_name)
            if not any([tag.startswith(probe_tag_filter) for tag in c.tags]):
                plugins_to_skip.append(
                    plugin_name
                )  # using list.remove doesn't update for-loop position

        for plugin_to_skip in plugins_to_skip:
            plugin_names.remove(plugin_to_skip)

    return plugin_names, unknown_plugins
