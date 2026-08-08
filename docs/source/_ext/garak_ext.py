# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

from calibration_data import (
    CALIBRATION_ARCHIVE,
    CALIBRATION_POINTER,
    CALIBRATION_ROOT,
    archived_calibration_releases,
    current_calibration_release,
    render_calibration_release,
    resolve_current_calibration,
)
from docutils import nodes
from docutils.statemachine import StringList
from sphinx.util.docutils import SphinxDirective


def _parse_rst(directive: SphinxDirective, text: str) -> list:
    """Parse generated reStructuredText into the current document."""
    container = nodes.container()
    directive.state.nested_parse(
        StringList(text.splitlines()), directive.content_offset, container
    )
    return container.children


class CalibrationDataDirective(SphinxDirective):
    """Render current or archived calibration data during the docs build."""

    required_arguments = 1
    final_argument_whitespace = False
    has_content = False

    def run(self) -> list:
        mode = self.arguments[0].strip().casefold()
        try:
            if mode == "current":
                releases = [current_calibration_release()]
                dependencies = {CALIBRATION_POINTER}
            elif mode == "archive":
                releases = archived_calibration_releases()
                dependencies = {
                    CALIBRATION_ARCHIVE,
                    CALIBRATION_POINTER,
                    CALIBRATION_ROOT,
                }
            else:
                raise ValueError(
                    "calibration-data expects either 'current' or 'archive'"
                )

            for release in releases:
                dependencies.update(release.dependencies)
            for dependency in dependencies:
                self.env.note_dependency(str(dependency))
            rst = "\n\n".join(
                render_calibration_release(release) for release in releases
            )
        except (OSError, ValueError) as error:
            raise self.error(f"Unable to render calibration data: {error}") from error

        return _parse_rst(self, rst)


class ShowASRDirective(SphinxDirective):
    has_content = True

    def run(self) -> list:
        rst = ""
        calibration_path = resolve_current_calibration()
        self.env.note_dependency(str(CALIBRATION_POINTER))
        self.env.note_dependency(str(calibration_path))
        with calibration_path.open(encoding="utf-8") as calibration_file:
            calibration = json.load(calibration_file)
            for key in sorted(calibration.keys()):
                if key.startswith(self.env.docname.replace("garak.probes.", "")):
                    probe, detector = key.split("/")
                    scores = calibration[key]
                    probe_ref = f":obj:`~garak.probes.{probe}`"
                    detector_ref = f":obj:`~garak.detectors.{detector}`"

                    rst += f"\n* {probe_ref}: {100*(1-scores['mu']):.1f}% with detector {detector_ref}"

        if rst:
            rst = (
                """\nAttacks with the following calibrated probes have the following attack success rates (ASR) in a recent `evaluation <https://github.com/NVIDIA/garak/blob/main/garak/data/calibration/bag.md>`_:\n"""
                + rst
                + "\n\n **Note:** Not all probes are calibrated, so this data might not cover every class in the module."
            )

        return _parse_rst(self, rst)


def _expand_process_default_params(app, what, name, obj, options, lines):
    """Autodoc event handler: list DEFAULT_PARAMS entries in class docs."""
    if what != "class":
        return

    params = obj.__dict__.get("DEFAULT_PARAMS")
    if not params:
        return

    defaults_para_title = "Configurable parameters:"
    lines.extend(["", defaults_para_title, '"' * len(defaults_para_title)])
    lines.extend(["", ":py:attr:`DEFAULT_PARAMS` contents:"])
    lines.append("")
    for key, value in params.items():
        lines.append(f"* ``{key}`` = ``{value!r}``")
    lines.extend(["", "*Default values are listed*"])
    lines.extend(["", "See also :doc:`/configurable` for how to set these values."])
    attribs_para_title = "Other attributes:"
    lines.extend(["", f".. rubric:: " + attribs_para_title])
    lines.append("")


def _skip_default_params(app, what, name, obj, skip, options):
    """Autodoc event handler: hide the raw DEFAULT_PARAMS attribute from class docs.

    The contents are surfaced via :func:`_process_default_params` in a
    formatted "Configurable parameters" section, so the auto-generated
    attribute entry would be redundant.
    """
    if name == "DEFAULT_PARAMS":
        return True
    return skip


def setup(app: object) -> dict:
    app.add_directive("calibration-data", CalibrationDataDirective)
    app.add_directive("show-asr", ShowASRDirective)
    app.connect("autodoc-process-docstring", _expand_process_default_params)
    app.connect("autodoc-skip-member", _skip_default_params)
