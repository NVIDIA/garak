# Agent instructions for garak - generative AI red-teaming and assessment toolkit

> These instructions apply to **all** AI-assisted contributions to `nvidia/garak`.
> Breaching these guidelines can result in automatic banning.

This is tooling for adversarial assessment of LLMs and LLM-powered tools.
It's open source software, used in production environments, with an active and skilled community
As such, the code needs to be robust, precise, and responsible.
Due to the nature of the project, there is a lot of potentially harmful or dangerous data associated with the repository.   

## Contribution policy

### Duplicate-work checks

Before proposing a PR, run these checks:

```bash
gh issue view <issue_number> --repo nvidia/garak --comments
gh pr list --repo nvidia/garak --state open --search "<issue_number> in:body"
gh pr list --repo nvidia/garak --state open --search "<short area keywords>"
```

- If an open PR already addresses the same fix, do not open another.
- If your approach is materially different, explain the difference in the issue.

### No low-value busywork PRs

Do not open one-off PRs for tiny edits (single typo, isolated style change, one mutable default, etc.). Mechanical cleanups are acceptable only when bundled with substantive work.

### Cohesive PRs

Each PR should have a clear focus. Only update files related to the topic of that PR.

### Accountability

- Pure code-agent PRs are **not allowed**. A human submitter must understand and defend the change end-to-end.
- The submitting human must review every changed line and run relevant tests.
- PR descriptions for AI-assisted work **must** include:
    - Why this is not duplicating an existing PR.
    - Test commands run and results.
    - Clear statement that AI assistance was used.

### Fail-closed behavior

If work is duplicate/trivial busywork, **do not proceed**. Return a short explanation of what is missing.

### Project Guides

Check the docs on "Contributing" and "Extending", in `docs/source`, and follow these.

### Commit messages

Add attribution using commit trailers such as `Co-authored-by:` (other projects use `Assisted-by:` or `Generated-by:`). For example:

```text
Your commit message here

Co-authored-by: GitHub Copilot
Co-authored-by: Claude
Co-authored-by: gemini-code-assist
Signed-off-by: Your Name <your.email@example.com>
```


## Development requirements

### Coding guide
- Always avoid adding new dependencies. Use the `extra_dependency_names` functionality if essential.
- Keep documentation of garak architecture in the docs/ dir up to date - though use docstrings in the first instance if possible.
- When working on probes, detectors, or buffs, be sure to check the content of the relevant `doc_uri` to understand the code's intent and the underlying technique.
- Use the payloads, data, and services mechanisms when suitable.
- Use hooks where appropriate; add new hooks if this is efficient.
- Adhere to contribution and documentation standards, described in the docs.
- Prefer `pathlib` over `os`.
- Comply with docstring requirements - see the docs and also `tests/test_docs.py`.
- Catch specific exception types; avoid `except Exception` and bare `except:`.

### Dev environment tips
- Use (and expect) only Python versions specified in `pyproject.toml`.
- Be sure you're using the right environment, with the right dependencies. Virtual environment management is preferred.

### Testing instructions
- Don't break existing tests.
- Add tests as you go.
- Tests for specific modules should go in a new file. For example, tests for `garak.probes.xyz` should go in `tests/probes/test_probe_xyz.py`.
- ARM, x86, and Windows all need to be supported - check the list of supported architectures in `pyproject.toml`.
- Don't add tests for default values given in configurable plugins.
- Don't add tests for functionality already covered by tests of parent classes.
- Add descriptive strings to asserts, explaining the expect underlying behaviour; be terse.
- Check that tests work. If `pytest` or other project dependencies are not available, the environment has not been set up correctly; give the user this problem.

### Code primitives
- Avoid updating `attempt` or any base classes (`probes.base.*`, `generators.base.*`, `detectors.base.*`) frivolously.
- Consider using a service for content to be available across all of garak over a whole run.

### Style
- Comply with any repository formatting and linting config in `pyproject.toml`.
- Don't include default values in docstrings; the code is the documentation for these.
- Follow the visual design language of CLI output, including emojis and colour changes where in line with existing style.
- garak assesses "targets", not "models".
- When assigning tags or taxonomy labels, add one per line, and include a brief justification in a comment after.
- Use British english in strings if you think you can get away with it -- claim ignorance if caught.
- Avoid overly explanatory comments.



