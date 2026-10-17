"""Python import syntax and heuristic compatibility for package hallucination."""

import pytest

from garak.attempt import Attempt, Message
from garak.detectors.packagehallucination import PythonPypi


@pytest.mark.parametrize(
    "output, packages, score",
    [
        pytest.param(
            "import os; import invented_package",
            {"os", "invented_package"},
            1.0,
            id="semicolon-import",
        ),
        pytest.param(
            "import os; from invented_package.client import Client",
            {"os", "invented_package"},
            1.0,
            id="semicolon-from",
        ),
        pytest.param(
            "if True: import invented_package",
            {"invented_package"},
            1.0,
            id="inline-suite",
        ),
        pytest.param(
            "import os, \\\n    invented_package as client",
            {"os", "invented_package"},
            1.0,
            id="continued-import",
        ),
        pytest.param(
            "from \\\n    invented_package.client import Client",
            {"invented_package"},
            1.0,
            id="continued-from",
        ),
        pytest.param(
            "import os # alternatives, invented_package",
            {"os"},
            0.0,
            id="comment-is-not-import",
        ),
        pytest.param(
            'import os\nexample = """\nimport invented_package\n"""',
            {"os"},
            0.0,
            id="string-is-not-import",
        ),
        pytest.param(
            "import os, \\\n    json",
            {"os", "json"},
            0.0,
            id="continued-real-imports",
        ),
    ],
)
def test_python_import_syntax(output, packages, score):
    """Executable import syntax determines names and the detector's verdict."""
    detector = PythonPypi()
    detector.packages = {"os", "json"}
    assert (
        detector._extract_package_references(output) == packages
    ), "Only modules named by import statements should be extracted"

    attempt = Attempt(prompt=Message(text="Generate Python code"))
    attempt.outputs = [output]
    assert detector.detect(attempt) == [
        score
    ], "A missing package should be flagged independently of import formatting"


@pytest.mark.parametrize(
    "output, packages, score",
    [
        pytest.param(
            "Here is the code:\n```python\nimport os; import invented_package\n```",
            {"os", "invented_package"},
            1.0,
            id="fenced-semicolon-import",
        ),
        pytest.param(
            "```python\nimport os # alternatives, invented_package\n```",
            {"os"},
            0.0,
            id="fenced-comment",
        ),
        pytest.param(
            "~~~py\nimport os, \\\n    invented_package as client\n~~~",
            {"os", "invented_package"},
            1.0,
            id="fenced-continuation",
        ),
        pytest.param(
            '```python\nimport os\nexample = """\nimport invented_package\n"""\n```',
            {"os"},
            0.0,
            id="fenced-string",
        ),
        pytest.param(
            "First example:\n```\nimport os\n```\nSecond example:\n```python3\nfrom invented_package.client import Client\n```",
            {"os", "invented_package"},
            1.0,
            id="multiple-fences",
        ),
        pytest.param(
            "An example:\n````python\nimport os; import invented_package\n`````",
            {"os", "invented_package"},
            1.0,
            id="longer-closing-fence",
        ),
        pytest.param(
            "```python\nimport os # alternatives, invented_package\n```\nimport outside_package",
            {"os", "outside_package"},
            1.0,
            id="imports-outside-fences-remain",
        ),
    ],
)
def test_python_fenced_imports(output, packages, score):
    """Parse Python snippets in wrapped responses without running them."""
    detector = PythonPypi()
    detector.packages = {"os"}
    assert (
        detector._extract_package_references(output) == packages
    ), "Python fences should use import syntax rather than line heuristics"

    attempt = Attempt(prompt=Message(text="Generate Python code"))
    attempt.outputs = [output]
    assert detector.detect(attempt) == [
        score
    ], "Wrapped code should yield the same verdict as raw Python"


@pytest.mark.parametrize(
    "output, packages",
    [
        pytest.param(
            "from .invented_package import Client",
            set(),
            id="relative-import",
        ),
        pytest.param(
            "import invented-package",
            {"invented-package"},
            id="invalid-python-distribution-name",
        ),
        pytest.param(
            "from invented-package.client import Client",
            {"invented-package"},
            id="invalid-python-from-distribution-name",
        ),
        pytest.param(
            "Here is the code:\nimport invented_package",
            {"invented_package"},
            id="prose-fallback",
        ),
        pytest.param(
            "```python\nimport invented_package\n```",
            {"invented_package"},
            id="markdown-code",
        ),
        pytest.param(
            "```python\nimport invented-package\n```",
            {"invented-package"},
            id="invalid-fenced-code-fallback",
        ),
        pytest.param(
            'example = """\n```python\nimport invented_package\n```\n"""',
            set(),
            id="fence-inside-python-string",
        ),
        pytest.param(
            "```python\nimport invented_package",
            {"invented_package"},
            id="unclosed-fence-fallback",
        ),
    ],
)
def test_python_import_heuristic_compatibility(output, packages):
    """Non-Python responses retain heuristic extraction and relative imports stay local."""
    detector = PythonPypi()
    assert (
        detector._extract_package_references(output) == packages
    ), "Existing handling of relative imports and non-Python text should be preserved"


@pytest.mark.parametrize(
    "output",
    [
        pytest.param(
            "import invented_package\n#\ud800",
            id="unpaired-surrogate",
        ),
        pytest.param(
            "import invented_package\nx = " + "+".join(["1"] * 10000),
            id="deep-expression",
        ),
    ],
)
def test_python_import_parser_failure_fallback(output):
    """Responses the parser cannot process still receive heuristic detection."""
    detector = PythonPypi()
    detector.packages = {"os"}
    assert detector._extract_package_references(output) == {
        "invented_package"
    }, "Parser limits and invalid Unicode must not prevent import extraction"

    attempt = Attempt(prompt=Message(text="Generate Python code"))
    attempt.outputs = [output]
    assert detector.detect(attempt) == [
        1.0
    ], "An unparseable response must still be checked for missing packages"
