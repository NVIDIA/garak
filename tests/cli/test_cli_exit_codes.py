"""Exit-code coverage for `garak.cli.main` (issue #1221).

The CLI used to log on error and return 0, which made `garak ms`-style
wrappers unable to detect failures. These tests pin the mapping between
the major exception classes raised inside the run pipeline and the exit
codes defined in `garak.exception`.
"""

import pytest

from garak import cli, exception


def _run_with_injected_exception(monkeypatch, exc: BaseException) -> int:
    """Drive cli.main with valid args, then raise from inside the run try-block.

    `parse_cli_plugin_config` is the first call inside the wrapping
    try/except in cli.main, so patching it lets us inject any exception
    type into the path that the outer handlers are supposed to catch.
    `--list_probes` keeps the rest of the run cheap and hermetic.
    """

    def _boom(*_args, **_kwargs):
        raise exc

    monkeypatch.setattr("garak.cli.parse_cli_plugin_config", _boom)

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--list_probes"])
    return excinfo.value.code


def test_keyboard_interrupt_uses_interrupted_code(monkeypatch):
    code = _run_with_injected_exception(monkeypatch, KeyboardInterrupt())
    assert code == exception.EXIT_INTERRUPTED


def test_bad_generator_uses_generator_code(monkeypatch):
    code = _run_with_injected_exception(
        monkeypatch, exception.BadGeneratorException("nope")
    )
    assert code == exception.EXIT_GENERATOR_ERROR


def test_config_failure_uses_config_code(monkeypatch):
    code = _run_with_injected_exception(
        monkeypatch, exception.ConfigFailure("missing field")
    )
    assert code == exception.EXIT_CONFIG_ERROR


def test_plugin_configuration_error_uses_config_code(monkeypatch):
    code = _run_with_injected_exception(
        monkeypatch, exception.PluginConfigurationError("bad plugin")
    )
    assert code == exception.EXIT_CONFIG_ERROR


def test_report_incompatible_uses_reporting_code(monkeypatch):
    code = _run_with_injected_exception(
        monkeypatch, exception.ReportIncompatibleError("old report")
    )
    assert code == exception.EXIT_REPORTING_ERROR


def test_generic_garak_exception_uses_unspecified_code(monkeypatch):
    code = _run_with_injected_exception(monkeypatch, exception.GarakException("?"))
    assert code == exception.EXIT_UNSPECIFIED


def test_value_error_uses_unspecified_code(monkeypatch):
    code = _run_with_injected_exception(monkeypatch, ValueError("bad value"))
    assert code == exception.EXIT_UNSPECIFIED


def test_exit_code_constants_are_distinct():
    """Guards against future edits that accidentally collide buckets."""
    codes = [
        exception.EXIT_OK,
        exception.EXIT_INTERRUPTED,
        exception.EXIT_PROBE_ERROR,
        exception.EXIT_GENERATOR_ERROR,
        exception.EXIT_DETECTOR_ERROR,
        exception.EXIT_BUFF_ERROR,
        exception.EXIT_EVALUATOR_ERROR,
        exception.EXIT_HARNESS_ERROR,
        exception.EXIT_LANGPROVIDER_ERROR,
        exception.EXIT_REPORTING_ERROR,
        exception.EXIT_OUT_OF_LOCAL_RESOURCES,
        exception.EXIT_CONFIG_ERROR,
        exception.EXIT_UNSPECIFIED,
    ]
    assert len(codes) == len(set(codes))
    # All codes must fit in an 8-bit unsigned int (shells truncate above 255).
    assert all(0 <= code <= 255 for code in codes)
