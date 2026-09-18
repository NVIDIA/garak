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


def test_list_probes_warns_on_rejected_intent_selector(capsys):
    """A malformed intent: code must not be silently dropped from the preview
    (the run path already reports it via _check_selection; --list_probes must too)."""
    cli.main(["--list_probes", "--spec", "probes.dan,intent:zzz"])
    out = capsys.readouterr().out
    assert "intent:zzz" in out, "the rejected selector must be named in the warning"

    lines = _plugin_lines(out)
    # print_plugins strips the "probes." category prefix before printing each name
    expected = {
        name.removeprefix("probes.")
        for name, active in _plugins.enumerate_plugins(category="probes")
        if active and name.startswith("probes.dan.")
    }
    assert expected, "fixture expects at least one active probes.dan.* plugin"
    assert all(
        any(name in ln for ln in lines) for name in expected
    ), "the malformed intent: code must leave the whole dan family unfiltered"


def test_list_buffs_warns_on_rejected_intent_selector(capsys):
    """The --list_buffs preview must warn on a malformed intent: code and still
    show the surviving buff, mirroring the --list_probes behaviour above."""
    active_buffs = {
        name for name, active in _plugins.enumerate_plugins(category="buffs") if active
    }
    assert (
        "buffs.lowercase.Lowercase" in active_buffs
    ), "fixture expects buffs.lowercase.Lowercase to be active"

    cli.main(["--list_buffs", "--spec", "buffs.lowercase,intent:zzz"])
    out = capsys.readouterr().out
    assert "intent:zzz" in out, "the rejected selector must be named in the warning"

    lines = _plugin_lines(out)
    assert all(ln.startswith("buffs: ") for ln in lines), "expected all 'buffs:' lines"
    # print_plugins strips the "buffs." category prefix before printing each name
    assert any(
        "lowercase.Lowercase" in ln for ln in lines
    ), "the malformed intent: code must leave the requested buff in the preview"


def test_list_probes_verbose_table(capsys):
    """Test that --list_probes -v outputs a markdown table with tier and description."""
    cli.main(["--list_probes", "-v"])
    output = capsys.readouterr().out
    # Should contain markdown table structure
    assert "|" in output, "expected markdown table with | delimiters"
    # Should contain the expected column headers
    assert "name" in output, "expected 'name' column header"
    assert "active" in output, "expected 'active' column header"
    assert "tier" in output, "expected 'tier' column header"
    assert "description" in output, "expected 'description' column header"
    # Should contain at least one tier enum name
    tier_names = ["OF_CONCERN", "COMPETE_WITH_SOTA", "INFORMATIONAL", "UNLISTED"]
    assert any(
        name in output for name in tier_names
    ), f"expected at least one tier name from {tier_names}"
    # Should contain active/inactive markers
    assert "✅" in output or "💤" in output, "expected active/inactive markers"
    # Module headers should have 🌟
    assert "🌟" in output, "expected module header markers"


def test_list_probes_verbose_with_probe_spec(capsys):
    """Test that --list_probes -v -p <spec> outputs a filtered markdown table."""
    cli.main(["--list_probes", "-v", "-p", "dan"])
    output = capsys.readouterr().out
    assert "|" in output, "expected markdown table"
    assert "dan" in output.lower(), "expected 'dan' probes in output"
