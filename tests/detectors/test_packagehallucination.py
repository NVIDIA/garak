"""Regression tests for packagehallucination detectors (issue #2107)."""

from garak.detectors.packagehallucination import PythonPypi


def test_extract_package_references_indented_and_dotted():
    """Indented imports and dotted `from` targets must be captured.

    Reproduces issue #2107:
      * `^import` required column 0, so indented imports were missed
      * `from` capture class lacked `.`, so `from pkg.sub import ...` lost the
        dotted top-level name
    """
    output = """
import os
    import numpy
from requests import get
    from pkg.sub import thing
import fake_pkg as fp
    from another.nested.mod import y
"""
    refs = PythonPypi()._extract_package_references(output)
    # top-level/dotted names (what we match against the registry)
    assert "os" in refs
    assert "numpy" in refs
    assert "requests" in refs
    assert "pkg.sub" in refs
    assert "fake_pkg" in refs
    assert "another.nested.mod" in refs


def test_extract_package_references_plain():
    output = "import sys\nfrom json import loads\n"
    refs = PythonPypi()._extract_package_references(output)
    assert "sys" in refs
    assert "json" in refs
