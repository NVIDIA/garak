# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

from docutils.frontend import OptionParser
from docutils.utils import new_document
from sphinx.util.docutils import SphinxDirective
from sphinx.parsers import RSTParser


class ShowASRDirective(SphinxDirective):
    has_content = True

    def run(self) -> list:
        rst = ""
        with open(
            "../../garak/data/calibration/calibration.json", encoding="utf-8"
        ) as f:
            calibration = json.load(f)
            for key in sorted(calibration.keys()):
                if key.startswith(self.env.docname.replace("garak.probes.", "")):
                    probe, detector = key.split("/")
                    scores = calibration[key]
                    probe_ref = f":obj:`~garak.probes.{probe}`"
                    detector_ref = f":obj:`~garak.detectors.{detector}`"

                    rst += f"\n* {probe_ref}: {100*(1-scores["mu"]):.1f}% with detector {detector_ref}"

        if rst:
            rst = (
                """\nAttacks with the following calibrated probes have the following attack success rates (ASR) in a recent `evaluation <https://github.com/NVIDIA/garak/blob/main/garak/data/calibration/bag.md>`_:\n"""
                + rst
                + "\n\n **Note:** Not all probes are calibrated, so this data might not cover every class in the module."
            )

        return self._parse_rst(rst)

    def _parse_rst(self, text):
        parser = RSTParser()
        parser.set_application(self.env.app)
        settings = OptionParser(
            defaults=self.env.settings,
            components=(RSTParser,),
            read_config_files=True,
        ).get_default_values()
        document = new_document("<rst-doc>", settings=settings)
        parser.parse(text, document)
        return document.children


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
    lines.extend(["", "See also :doc:`configurable` for how to set these values."])
    lines.extend(["", "----"])
    attribs_para_title = "Other attributes:"
    lines.extend(["", attribs_para_title, '"' * len(attribs_para_title)])
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
    app.add_directive("show-asr", ShowASRDirective)
    app.connect("autodoc-process-docstring", _expand_process_default_params)
    app.connect("autodoc-skip-member", _skip_default_params)
