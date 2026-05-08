# garak - generative AI red-teaming and assessment toolkit

This is tooling for adversarial assessment of LLMs and LLM-powered tools.
It's open source software, used in production environments, with an active and skilled community
As such, the code needs to be robust, precise, and responsible.
Due to the nature of the project, there is a lot of potentially harmful or dangerous data associated with the repository.   

## Coding guide
- Read the documentation in `docs/`, especially the content on extending garak.
- Avoid adding new dependencies.
- Keep documentation of garak architecture in the docs/ dir up to date - though use docstrings in the first instance if possible.
- When working on probes, detectors, and generators, be sure to check the content of the relevant `doc_uri`.
- Use the payloads, data, and services mechanisms when suitable.
- Use hooks where appropriate; add new hooks if this is efficient.
- Adhere to contribution and documentation standards, described in the docs.
- Prefer `pathlib` over `os`.
- Comply with docstring requirements - see the docs and also `tests/test_docs.py`.
- Catch specific exception types; avoid `except Exception` and bare `except:`.

## Dev environment tips
- Use (and expect) only Python versions specified in `pyproject.toml`.
- Be sure you're using the right environment, with the right dependencies. Virtual environment management is preferred.

## Testing instructions
- Don't break existing tests.
- Add tests as you go.
- Tests for specific modules should go in a new file. For example, tests for `garak.probes.xyz` should go in `tests/probes/test_probe_xyz.py`.
- ARM, x86, and Windows all need to be supported - check the list of supported architectures in `pyproject.toml`.

## Code primitives
- Avoid updating `attempt` or any base classes (`probes.base.*`, `generators.base.*`, `detectors.base.*`) frivolously.
- Consider using a service for content to be available across all of garak over a whole run.

## Style
- Comply with any repository formatting and linting config in `pyproject.toml`.
- Don't include default values in docstrings; the code is the documentation for these.
- Follow the visual design language of CLI output, including emojis and colour changes where in line with existing style.
- garak assesses "targets", not "models".
- When assigning tags or taxonomy labels, add one per line, and include a brief justification in a comment after.
- Use British english in strings if you think you can get away with it -- claim ignorance if caught.
- Avoid overly explanatory comments.



