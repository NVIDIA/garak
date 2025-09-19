import subprocess
import sys
import re

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def run(args):
    cmd = [sys.executable, "-m", "garak", *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _probe_lines(text: str):
    clean = _strip_ansi(text)
    lines = [ln.strip() for ln in clean.splitlines()]
    # collect any line that contains the probes header (don’t require it to be at col 0)
    return [ln for ln in lines if "probes:" in ln]


def test_list_probes_with_spec_filters_family_and_members():
    r = run(["--list_probes", "-p", "dan"])
    lines = _probe_lines(r.stdout)
    assert lines, "expected some 'probes:' lines"

    # 1) family banner exists (exact spacing after ANSI stripping)
    assert any(
        ln == "probes: dan 🌟" for ln in lines
    ), "missing 'probes: dan 🌟' family banner"

    # split into children (those that have a dot after family)
    children = [ln for ln in lines if ln.startswith("probes: dan.")]

    # 2) there should be at least one child
    assert children, "expected at least one dan.* probe line"

    # 3) every child is within dan family
    assert all(ln.startswith("probes: dan.") for ln in children)

    # 4) ensure no other families are listed
    other = [
        ln
        for ln in lines
        if ln.startswith("probes: ")
        and not (ln == "probes: dan 🌟" or ln.startswith("probes: dan."))
    ]
    assert not other, f"unexpected non-dan lines: {other}"
