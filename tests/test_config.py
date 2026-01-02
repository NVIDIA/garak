# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import json
import os
from pathlib import Path
import pytest
import re
import shutil
import sys
import tempfile

from pytest_httpserver import HTTPServer

from garak import _config
import garak.cli


SITE_YAML_FILENAME = "TESTONLY.site.yaml.bak"
CONFIGURABLE_YAML = """
plugins:
  generators:
    huggingface:
      hf_args:
        torch_dtype: float16
      Pipeline:
        hf_args:
            device: cuda
  probes:
    test:
      generators:
        huggingface:
            Pipeline:
                hf_args:
                    torch_dtype: float16
  detector:
      test:
        val: tests
        Blank:
          generators:
            huggingface:
                hf_args:
                    torch_dtype: float16
                    device: cuda:1
                Pipeline:
                  dtype: for_detector
  buffs:
      test:
        Blank:
          generators:
            huggingface:
                hf_args:
                    device: cuda:0
                Pipeline:
                  dtype: for_detector
""".encode(
    "utf-8"
)

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
XDG_VARS = ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME")

OPTIONS_SOLO = [
    #    "verbose", # not sure hot to test argparse action="count"
    #    "deprefix", # this param is weird
    "narrow_output",
    "extended_detectors",
]
OPTIONS_PARAM = [
    ("report_prefix", "laurelhurst"),
    ("parallel_requests", 9),
    ("parallel_attempts", 9),
    ("seed", 9001),
    ("eval_threshold", 0.9),
    ("generations", 9),
    #    ("config", "obsidian.yaml"), # optional config file names passed via CLI don't get stored in _config. that'll suck to troubleshoot
    ("target_type", "test"),
    ("target_name", "bruce"),
]
OPTIONS_SPEC = [
    ("probes", "3,elim,gul.dukat", "probe_spec"),
    ("detectors", "all", "detector_spec"),
    ("buffs", "polymorph", "buff_spec"),
]

param_locs = {}
for p in _config.system_params:
    param_locs[p] = "system"
for p in _config.run_params:
    param_locs[p] = "run"
for p in _config.plugins_params:
    param_locs[p] = "plugins"
for p in _config.reporting_params:
    param_locs[p] = "reporting"


@pytest.fixture
def allow_site_config(request):
    site_cfg_moved = False
    try:
        shutil.move(
            _config.transient.config_dir / "garak.site.yaml", SITE_YAML_FILENAME
        )
        site_cfg_moved = True
    except FileNotFoundError:
        site_cfg_moved = False

    def restore_site_config():
        if site_cfg_moved:
            shutil.move(
                SITE_YAML_FILENAME, _config.transient.config_dir / "garak.site.yaml"
            )
        elif os.path.exists(_config.transient.config_dir / "garak.site.yaml"):
            os.remove(_config.transient.config_dir / "garak.site.yaml")

    request.addfinalizer(restore_site_config)


@pytest.fixture
def override_xdg_env(request):
    restore_vars = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        for env_var in XDG_VARS:
            current_val = os.getenv(env_var, None)
            if current_val is not None:
                restore_vars[env_var] = current_val
            os.environ[env_var] = tmpdir

    def restore_xdg_env():
        for env_var in XDG_VARS:
            restored = restore_vars.get(env_var)
            if restored is not None:
                os.environ[env_var] = restored
            else:
                del os.environ[env_var]

    request.addfinalizer(restore_xdg_env)

    return tmpdir


@pytest.fixture
def clear_xdg_env(request):
    restore_vars = {}
    for env_var in XDG_VARS:
        current_val = os.getenv(env_var, None)
        if current_val is not None:
            restore_vars[env_var] = current_val
            del os.environ[env_var]

    def restore_xdg_env():
        for env_var in XDG_VARS:
            restored = restore_vars.get(env_var)
            if restored is not None:
                os.environ[env_var] = restored
            else:
                try:
                    del os.environ[env_var]
                except KeyError as e:
                    pass

    request.addfinalizer(restore_xdg_env)


# environment variables adjust transient values
def test_xdg_support(override_xdg_env):
    test_path = Path(override_xdg_env)

    importlib.reload(_config)

    assert _config.transient.cache_dir == test_path / _config.project_dir_name
    assert _config.transient.config_dir == test_path / _config.project_dir_name
    assert _config.transient.data_dir == test_path / _config.project_dir_name


@pytest.mark.usefixtures("clear_xdg_env")
def test_xdg_defaults():
    if "HOME" in os.environ:
        test_path = Path(os.environ["HOME"])
    elif sys.platform == "win32" and "USERPROFILE" in os.environ:
        # the xdg lib returns values prefixed with "USERPROFILE" on windows
        test_path = Path(os.environ["USERPROFILE"])

    importlib.reload(_config)

    assert (
        _config.transient.cache_dir == test_path / ".cache" / _config.project_dir_name
    )
    assert (
        _config.transient.config_dir == test_path / ".config" / _config.project_dir_name
    )
    assert (
        _config.transient.data_dir
        == test_path / ".local" / "share" / _config.project_dir_name
    )


# test CLI assertions of each var
@pytest.mark.parametrize("option", OPTIONS_SOLO)
def test_cli_solo_settings(option):
    importlib.reload(_config)

    garak.cli.main(
        [f"--{option}", "--list_config"]
    )  # add list_config as the action so we don't actually run
    subconfig = getattr(_config, param_locs[option])
    assert getattr(subconfig, option) == True


@pytest.mark.parametrize("param", OPTIONS_PARAM)
def test_cli_param_settings(param):
    importlib.reload(_config)

    option, value = param
    garak.cli.main(
        [f"--{option}", str(value), "--list_config"]
    )  # add list_config as the action so we don't actually run
    subconfig = getattr(_config, param_locs[option])
    assert getattr(subconfig, option) == value


@pytest.mark.parametrize("param", OPTIONS_SPEC)
def test_cli_spec_settings(param):
    importlib.reload(_config)

    option, value, configname = param
    garak.cli.main(
        [f"--{option}", str(value), "--list_config"]
    )  # add list_config as the action so we don't actually run
    assert getattr(_config.plugins, configname) == value


# test a short-form CLI assertion
def test_cli_shortform():
    importlib.reload(_config)

    garak.cli.main(["-s", "444", "--list_config"])
    assert _config.run.seed == 444
    if _config.transient.reportfile is not None:
        _config.transient.reportfile.close()
        if os.path.exists(_config.transient.report_filename):
            os.remove(_config.transient.report_filename)

    garak.cli.main(
        ["-g", "444", "--list_config"]
    )  # seed gets special treatment, try another
    assert _config.run.generations == 444


# test that run YAML overrides core YAML
@pytest.mark.parametrize("param", OPTIONS_PARAM)
def test_yaml_param_settings(param):
    importlib.reload(_config)

    option, value = param
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        file_data = [
            f"---",
            f"{param_locs[option]}:",
            f"  {option}: {value}",
        ]
        tmp.write("\n".join(file_data).encode("utf-8"))
        tmp.close()
        garak.cli.main(
            ["--config", tmp.name, "--list_config"]
        )  # add list_config as the action so we don't actually run
        subconfig = getattr(_config, param_locs[option])
        os.remove(tmp.name)
        assert (
            getattr(subconfig, option) == value
        ), f"CLI-supplied config values for {option} should override core config"


# # test that site YAML overrides core YAML # needs file staging for site yaml
@pytest.mark.usefixtures("allow_site_config")
def test_site_yaml_overrides_core_yaml():
    importlib.reload(_config)

    with open(
        _config.transient.config_dir / "garak.site.yaml", "w", encoding="utf-8"
    ) as f:
        f.write("---\nrun:\n  eval_threshold: 0.777\n")
        f.flush()
        garak.cli.main(["--list_config"])

    assert (
        _config.run.eval_threshold == 0.777
    ), "Site config should override core config if loaded correctly"


# # test that run YAML overrides site YAML # needs file staging for site yaml
@pytest.mark.usefixtures("allow_site_config")
def test_run_yaml_overrides_site_yaml():
    importlib.reload(_config)

    with open(
        _config.transient.config_dir / "garak.site.yaml", "w", encoding="utf-8"
    ) as f:
        file_data = [
            "---",
            "run:",
            "  eval_threshold: 0.777",
        ]
        f.write("\n".join(file_data))
        f.flush()
        garak.cli.main(["--list_config", "--eval_threshold", str(0.9001)])

    assert (
        _config.run.eval_threshold == 0.9001
    ), "CLI-specified config values should override site config"


# test that CLI config overrides run YAML
def test_cli_overrides_run_yaml():
    importlib.reload(_config)

    orig_seed = 10101
    override_seed = 37176
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        file_data = [
            f"---",
            f"run:",
            f"  seed: {orig_seed}",
        ]
        tmp.write("\n".join(file_data).encode("utf-8"))
        tmp.close()
        garak.cli.main(
            ["--config", tmp.name, "-s", f"{override_seed}", "--list_config"]
        )  # add list_config as the action so we don't actually run
        os.remove(tmp.name)
        assert (
            _config.run.seed == override_seed
        ), "CLI-specificd config values should override values in config file names on CLI"


# test probe_options YAML
# more refactor for namespace keys
def test_probe_options_yaml(capsys):
    importlib.reload(_config)

    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            "\n".join(
                [
                    "---",
                    "plugins:",
                    "  probe_spec: test.Blank",
                    "  probes:",
                    "    test:",
                    "      Blank:",
                    "        gen_x: 37176",
                ]
            ).encode("utf-8")
        )
        tmp.close()
        garak.cli.main(
            ["--config", tmp.name, "--list_config"]
        )  # add list_config as the action so we don't actually run
        os.remove(tmp.name)
        # is this right? in cli probes get expanded into the namespace.class format
        assert _config.plugins.probes["test"]["Blank"]["gen_x"] == 37176


# test generator_options YAML
# more refactor for namespace keys
def test_generator_options_yaml(capsys):
    importlib.reload(_config)

    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            "\n".join(
                [
                    "---",
                    "plugins:",
                    "  target_type: test.Blank",
                    "  probe_spec: test.Blank",
                    "  generators:",
                    "    test:",
                    "      test_val: test_value",
                    "      Blank:",
                    "        test_val: test_blank_value",
                    "        gen_x: 37176",
                ]
            ).encode("utf-8")
        )
        tmp.close()
        garak.cli.main(
            ["--config", tmp.name, "--list_config"]
        )  # add list_config as the action so we don't actually run
        os.remove(tmp.name)
        assert _config.plugins.generators["test"]["Blank"]["gen_x"] == 37176
        assert (
            _config.plugins.generators["test"]["Blank"]["test_val"]
            == "test_blank_value"
        )


# can a run be launched from a run YAML?
def test_run_from_yaml(capsys):
    importlib.reload(_config)

    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            "\n".join(
                [
                    "---",
                    "run:",
                    "  generations: 10",
                    "",
                    "plugins:",
                    "  target_type: test.Blank",
                    "  probe_spec: test.Blank",
                ]
            ).encode("utf-8")
        )
        tmp.close()
        garak.cli.main(["--config", tmp.name])
        os.remove(tmp.name)
    result = capsys.readouterr()
    output = result.out
    all_output = ""
    for line in output.strip().split("\n"):
        line = ANSI_ESCAPE.sub("", line)
        all_output += line

    assert "loading generator: Test: Blank" in all_output
    assert "queue of probes: test.Blank" in all_output
    assert "ok on   10/  10" in all_output
    assert "any.AnyOutput:" in all_output
    assert "test.Blank" in all_output
    assert "garak run complete" in all_output


# cli generator options file loads
# more refactor for namespace keys
@pytest.mark.usefixtures("allow_site_config")
def test_cli_generator_options_file():
    importlib.reload(_config)

    # write an options file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        json.dump({"test": {"Blank": {"this_is_a": "generator"}}}, tmp)
        tmp.close()
        # invoke cli
        garak.cli.main(
            ["--generator_option_file", tmp.name, "--list_config"]
        )  # add list_config as the action so we don't actually run
        os.remove(tmp.name)

        # check it was loaded
        assert _config.plugins.generators["test"]["Blank"] == {"this_is_a": "generator"}


# cli generator options file loads
# more refactor for namespace keys
def test_cli_probe_options_file():
    importlib.reload(_config)

    # write an options file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        json.dump({"test": {"Blank": {"probes_in_this_config": 1}}}, tmp)
        tmp.close()
        # invoke cli
        garak.cli.main(
            ["--probe_option_file", tmp.name, "--list_config"]
        )  # add list_config as the action so we don't actually run
        os.remove(tmp.name)

        # check it was loaded
        assert _config.plugins.probes["test"]["Blank"] == {"probes_in_this_config": 1}


# cli probe config file overrides yaml probe config (using combine into)
# more refactor for namespace keys
def test_cli_probe_options_overrides_yaml_probe_options():
    importlib.reload(_config)

    # write an options file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as probe_json_file:
        json.dump({"test": {"Blank": {"goal": "taken from CLI JSON"}}}, probe_json_file)
        probe_json_file.close()
        with tempfile.NamedTemporaryFile(buffering=0, delete=False) as probe_yaml_file:
            probe_yaml_file.write(
                "\n".join(
                    [
                        "---",
                        "plugins:",
                        "    probes:",
                        "        test:",
                        "            Blank:",
                        "                goal: taken from CLI YAML",
                    ]
                ).encode("utf-8")
            )
            probe_yaml_file.close()
            # invoke cli
            garak.cli.main(
                [
                    "--config",
                    probe_yaml_file.name,
                    "--probe_option_file",
                    probe_json_file.name,
                    "--list_config",
                ]
            )  # add list_config as the action so we don't actually run
            os.remove(probe_json_file.name)
            os.remove(probe_yaml_file.name)
        # check it was loaded
        assert _config.plugins.probes["test"]["Blank"]["goal"] == "taken from CLI JSON"


# cli should override yaml options
def test_cli_generator_options_overrides_yaml_probe_options():
    importlib.reload(_config)

    cli_generations_count = 9001
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as generator_yaml_file:
        generator_yaml_file.write(
            "\n".join(
                [
                    "---",
                    "run:",
                    "    generations: 999",
                ]
            ).encode("utf-8")
        )
        generator_yaml_file.close()
        args = [
            "--config",
            generator_yaml_file.name,
            "-g",
            str(cli_generations_count),
            "--list_config",
        ]  # add list_config as the action so we don't actually run
        garak.cli.main(args)
        os.remove(generator_yaml_file.name)
    # check it was loaded
    assert _config.run.generations == cli_generations_count


# check that probe picks up yaml config items
# more refactor for namespace keys
def test_blank_probe_instance_loads_yaml_config():
    importlib.reload(_config)
    import garak._plugins

    probe_name = "test.Blank"
    probe_namespace, probe_klass = probe_name.split(".")
    revised_goal = "TEST GOAL make the model forget what to output"
    generations = 5
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            "\n".join(
                [
                    f"---",
                    f"plugins:",
                    f"  probes:",
                    f"    {probe_namespace}:",
                    f"      {probe_klass}:",
                    f"        generations: {generations}",  # generations is required when cli called without a model
                    f"        goal: {revised_goal}",
                ]
            ).encode("utf-8")
        )
        tmp.close()
        output = garak.cli.main(["--config", tmp.name, "-p", probe_name])
        os.remove(tmp.name)
    probe = garak._plugins.load_plugin(f"probes.{probe_name}")
    assert probe.goal == revised_goal


# check that probe picks up cli config items
# more refactor for namespace keys
def test_blank_probe_instance_loads_cli_config():
    importlib.reload(_config)
    import garak._plugins

    probe_name = "test.Blank"
    probe_namespace, probe_klass = probe_name.split(".")
    revised_goal = "TEST GOAL make the model forget what to output"
    args = [
        "-p",
        probe_name,
        "--probe_options",
        json.dumps(
            {
                probe_namespace: {probe_klass: {"goal": revised_goal, "generations": 5}}
            }  # generations is required when cli called without a model
        ),
    ]
    garak.cli.main(args)
    probe = garak._plugins.load_plugin(f"probes.{probe_name}")
    assert probe.goal == revised_goal


# check that generator picks up yaml config items
# more refactor for namespace keys
def test_blank_generator_instance_loads_yaml_config():
    importlib.reload(_config)
    import garak._plugins

    generator_name = "test.Blank"
    generator_namespace, generator_klass = generator_name.split(".")
    revised_temp = 0.9001
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        tmp.write(
            "\n".join(
                [
                    f"---",
                    f"plugins:",
                    f"  generators:",
                    f"      {generator_namespace}:",
                    f"        temperature: {revised_temp}",
                    f"        {generator_klass}:",
                    f"          test_val: test_blank_value",
                ]
            ).encode("utf-8")
        )
        tmp.close()
        garak.cli.main(
            ["--config", tmp.name, "--target_type", generator_name, "--probes", "none"]
        )
        os.remove(tmp.name)
    gen = garak._plugins.load_plugin(f"generators.{generator_name}")
    assert gen.temperature == revised_temp
    assert gen.test_val == "test_blank_value"


# check that generator picks up cli config items
# more refactor for namespace keys
def test_blank_generator_instance_loads_cli_config():
    importlib.reload(_config)
    import garak._plugins

    generator_name = "test.Repeat"
    generator_namespace, generator_klass = generator_name.split(".")
    revised_temp = 0.9001
    args = [
        "--target_type",
        "test.Blank",
        "--probes",
        "none",
        "--generator_options",
        json.dumps(
            {generator_namespace: {generator_klass: {"temperature": revised_temp}}}
        )
        .replace(" ", "")
        .strip(),
    ]
    garak.cli.main(args)
    gen = garak._plugins.load_plugin(f"generators.{generator_name}")
    assert gen.temperature == revised_temp


# test parsing of probespec
def test_probespec_loading():
    assert _config.parse_plugin_spec(None, "detectors") == ([], [])
    assert _config.parse_plugin_spec("", "generators") == ([], [])
    assert _config.parse_plugin_spec("Auto", "probes") == ([], [])
    assert _config.parse_plugin_spec("NONE", "probes") == ([], [])
    # reject unmatched spec entires
    assert _config.parse_plugin_spec("probedoesnotexist", "probes") == (
        [],
        ["probedoesnotexist"],
    )
    assert _config.parse_plugin_spec("atkgen,probedoesnotexist", "probes") == (
        ["probes.atkgen.Tox"],
        ["probedoesnotexist"],
    )
    assert _config.parse_plugin_spec("atkgen.Tox,probedoesnotexist", "probes") == (
        ["probes.atkgen.Tox"],
        ["probedoesnotexist"],
    )
    # reject unmatched spec entires for unknown class
    assert _config.parse_plugin_spec(
        "atkgen.Tox,atkgen.ProbeDoesNotExist", "probes"
    ) == (["probes.atkgen.Tox"], ["atkgen.ProbeDoesNotExist"])
    # accept known disabled class
    assert _config.parse_plugin_spec("dan.DanInTheWild", "probes") == (
        ["probes.dan.DanInTheWild"],
        [],
    )
    # gather all class entires for namespace
    assert _config.parse_plugin_spec("atkgen", "probes") == (["probes.atkgen.Tox"], [])
    assert _config.parse_plugin_spec("always", "detectors") == (
        [
            "detectors.always.Fail",
            "detectors.always.Pass",
            "detectors.always.Passthru",
            "detectors.always.Random",
        ],
        [],
    )
    # reject all unknown class entires for namespace
    assert _config.parse_plugin_spec(
        "long.test.class,another.long.test.class", "probes"
    ) == ([], ["long.test.class", "another.long.test.class"])


def test_buff_config_assertion():
    importlib.reload(_config)
    import garak._plugins

    test_value = 9001
    _config.plugins.buffs["paraphrase"] = {"Fast": {"num_beams": test_value}}
    p = garak._plugins.load_plugin("buffs.paraphrase.Fast")
    assert p.num_beams == test_value


def test_tag_filter():
    assert _config.parse_plugin_spec(
        "atkgen", "probes", probe_tag_filter="LOL NULL"
    ) == ([], [])
    assert _config.parse_plugin_spec("*", "probes", probe_tag_filter="avid") != ([], [])
    assert _config.parse_plugin_spec("all", "probes", probe_tag_filter="owasp:llm") != (
        [],
        [],
    )
    found, rejected = _config.parse_plugin_spec(
        "all", "probes", probe_tag_filter="risk-cards:lmrc:sexual_content"
    )
    assert "probes.lmrc.SexualContent" in found


# when provided an absolute path as `reporting.report_dir` do not used `user_data_dir`
def test_report_dir_full_path():
    importlib.reload(_config)

    with tempfile.TemporaryDirectory() as tmpdir:

        report_path = Path(tmpdir).absolute()
        with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
            tmp.write(
                "\n".join(
                    [
                        f"---",
                        f"reporting:",
                        f"  report_dir: {report_path}",
                    ]
                ).encode("utf-8")
            )
            tmp.close()
            garak.cli.main(
                f"-m test.Blank --report_prefix abs_path_test -p test.Blank -d always.Fail --config {tmp.name}".split()
            )
            os.remove(tmp.name)
            assert os.path.isfile(report_path / "abs_path_test.report.jsonl")
            assert os.path.isfile(report_path / "abs_path_test.report.html")
            assert os.path.isfile(report_path / "abs_path_test.hitlog.jsonl")


# report prefix is used only for filename, report_dir is placed in user_data_dir
def test_report_prefix_with_hitlog_no_explode():
    importlib.reload(_config)

    garak.cli.main(
        "-m test.Blank --report_prefix kjsfhgkjahpsfdg -p test.Blank -d always.Fail".split()
    )
    report_path = Path(_config.transient.report_filename).parent
    assert _config.reporting.report_dir in str(report_path)
    assert str(_config.transient.data_dir) in str(report_path)
    assert os.path.isfile(report_path / "kjsfhgkjahpsfdg.report.jsonl")
    assert os.path.isfile(report_path / "kjsfhgkjahpsfdg.report.html")
    assert os.path.isfile(report_path / "kjsfhgkjahpsfdg.hitlog.jsonl")


def test_nested():
    importlib.reload(_config)

    _config.plugins.generators["a"]["b"]["c"]["d"] = "e"
    assert _config.plugins.generators["a"]["b"]["c"]["d"] == "e"


def test_get_user_agents():
    agents = _config.get_http_lib_agents()
    assert isinstance(agents, dict)


AGENT_TEST = "garak/9 - only simple tailors edition"


def test_set_agents():
    from requests import utils
    import httpx
    import aiohttp

    _config.set_all_http_lib_agents(AGENT_TEST)

    assert str(utils.default_user_agent()) == AGENT_TEST
    assert httpx._client.USER_AGENT == AGENT_TEST
    assert aiohttp.client_reqrep.SERVER_SOFTWARE == AGENT_TEST


def httpserver():
    return HTTPServer()


def test_agent_is_used_requests(httpserver: HTTPServer):
    import requests

    _config.set_http_lib_agents({"requests": AGENT_TEST})
    httpserver.expect_request(
        "/", headers={"User-Agent": AGENT_TEST}
    ).respond_with_data("")
    assert requests.get(httpserver.url_for("/")).status_code == 200


def test_agent_is_used_httpx(httpserver: HTTPServer):
    import httpx

    _config.set_http_lib_agents({"httpx": AGENT_TEST})
    httpserver.expect_request(
        "/", headers={"User-Agent": AGENT_TEST}
    ).respond_with_data("")
    assert httpx.get(httpserver.url_for("/")).status_code == 200


def test_agent_is_used_aiohttp(httpserver: HTTPServer):
    import aiohttp
    import asyncio

    _config.set_http_lib_agents({"aiohttp": AGENT_TEST})

    async def main():
        async with aiohttp.ClientSession() as session:
            async with session.get(httpserver.url_for("/")) as response:
                html = await response.text()

    httpserver.expect_request(
        "/", headers={"User-Agent": AGENT_TEST}
    ).respond_with_data("")
    asyncio.run(main())


def test_api_key_in_config():
    importlib.reload(_config)

    _config.plugins.generators["a"]["b"]["c"]["api_key"] = "something"
    assert _config._key_exists(_config.plugins.generators, "api_key")


# test max_workers applies when used in site config
@pytest.mark.usefixtures("allow_site_config")
def test_site_yaml_overrides_max_workers(capsys):
    importlib.reload(_config)

    with open(
        _config.transient.config_dir / "garak.site.yaml", "w", encoding="utf-8"
    ) as f:
        f.write("---\nsystem:\n  max_workers: 2\n")
        f.flush()
        garak.cli.main(["--list_config"])

    assert (
        _config.system.max_workers == 2
    ), "Site config worker count should override core config if loaded correctly"

    importlib.reload(_config)

    with pytest.raises(SystemExit) as exc_info:
        garak.cli.main("--parallel_attempts 3 -m test -p test.Test".split())
        result = capsys.readouterr()
        assert (
            result.split("\n")[-1]
            == "ValueError: Parallel worker count capped at 2 (config.system.max_workers)"
        )
        assert exc_info.type == SystemExit
        assert exc_info.value.code == 1


model_target_data = [
    ("model_type", "model_name"),
    ("model_type", "target_name"),
    ("target_type", "model_name"),
    ("target_type", "target_name"),
]


@pytest.mark.parametrize("type_key,name_key", model_target_data)
def test_model_target_switching(type_key, name_key):

    yaml_template = """
    plugins:
        {{typekey}}: {{typeval}}
        {{namekey}}: {{nameval}}
    """
    demo_type = "test.Test"
    demo_name = "9218-Black"

    yaml_template = yaml_template.replace("{{typeval}}", demo_type).replace(
        "{{nameval}}", demo_name
    )

    candidate_yaml = yaml_template.replace("{{typekey}}", type_key).replace(
        "{{namekey}}", name_key
    )
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as t:
        t.write(candidate_yaml)
        t.close()
        c = _config._load_yaml_config([t.name])
        assert c["plugins"]["target_name"] == demo_name
        assert c["plugins"]["target_type"] == demo_type


def test_model_target_override():

    yaml_template = """
    plugins:
        target_type: {{typeval}}
        target_name: {{nameval}}
        model_type: donky.Bonky
        model_name: obsidian
    """
    demo_type = "test.Test"
    demo_name = "9218-Black"
    candidate_yaml = yaml_template.replace("{{typeval}}", demo_type).replace(
        "{{nameval}}", demo_name
    )

    with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as t:
        t.write(candidate_yaml)
        t.close()
        c = _config._load_yaml_config([t.name])
        assert c["plugins"]["target_name"] == demo_name
        assert c["plugins"]["target_type"] == demo_type
