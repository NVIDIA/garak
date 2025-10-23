import pytest
import re

from garak import cli, _plugins

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _plugin_lines(text: str):
    clean = _strip_ansi(text)
    lines = [ln.strip() for ln in clean.splitlines()]
    # collect any line that contains a plugin prefix (don’t require it to be at col 0)
    plugin_lines = []
    for plugin_type in _plugins.PLUGIN_TYPES:
        [plugin_lines.append(ln) for ln in lines if f"{plugin_type}:" in ln]
    return plugin_lines


@pytest.mark.parametrize(
    "options",
    [
        ("--list_probes",),
        ("--list_probes", "-p", "dan"),
        ("--list_probes", "-p", "dan,dan.AntiDAN"),
    ],
)
def test_list_probes_with_probe_spec(capsys, options):
    cli.main(options)
    lines = _plugin_lines(capsys.readouterr().out)
    assert all(
        ln.startswith("probes: ") for ln in lines
    ), "expected all 'probes:' lines"

    if len(options) > 1:
        parts = options[2].split(",")
        assert all(
            any(part in ln for part in parts) for ln in lines
        ), "expected all spec values to be present"
    else:
        # look for active and family listing
        assert any("🌟" in ln for ln in lines)
        assert any("💤" in ln for ln in lines)


@pytest.mark.parametrize(
    "options",
    [
        ("--list_detectors",),
        ("--list_detectors", "-d", "unsafe_content"),
        ("--list_detectors", "-d", "unsafe_content,shields.Up"),
    ],
)
def test_list_probes_with_detector_spec(capsys, options):
    cli.main(options)
    lines = _plugin_lines(capsys.readouterr().out)
    assert all(
        ln.startswith("detectors: ") for ln in lines
    ), "expected all 'detectors:' lines"

    if len(options) > 1:
        parts = options[2].split(",")
        assert all(
            any(part in ln for part in parts) for ln in lines
        ), "expected all spec values to be present"
    else:
        assert any("🌟" in ln for ln in lines)
