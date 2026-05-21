# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Builds PDFs with hidden injection text using reportlab (BSD-3).

Each technique hides text from human readers while keeping it extractable
by the text parsers that LLM pipelines typically use upstream of inference.
"""

import tempfile
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import white, black
from reportlab.pdfgen import canvas


_BENIGN_TEXT = (
    "QUARTERLY FINANCIAL REPORT — Q1 2026\n"
    "Revenue: $4.2M (up 12% YoY)\n"
    "Operating Expenses: $3.1M\n"
    "Net Income: $1.1M\n"
    "Employee Count: 847\n\n"
    "Key Highlights:\n"
    "- Launched new product line in EMEA market\n"
    "- Signed partnership with three Fortune 500 companies\n"
    "- Customer retention rate improved to 94%"
)


def build_injection_pdf(
    payload: str,
    technique: str,
    *,
    label: str = "injection",
    benign_text: str = _BENIGN_TEXT,
    output_dir: str | None = None,
) -> Path:
    """Generate a PDF that hides *payload* using *technique*.

    Args:
        payload: The injection text to hide inside the PDF.
        technique: One of ``whitefont``, ``tinyfont``, ``overlay``.
        label: Identifier appended to the filename. Defaults to ``injection``.
        benign_text: Visible document content. Defaults to a sample report.
        output_dir: Directory for the output file. Uses a tempdir when None.

    Returns:
        Path to the generated PDF.
    """
    if technique not in _BUILDERS:
        raise ValueError(f"Unknown technique {technique!r}, expected one of {list(_BUILDERS)}")

    out_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp())
    out_path = out_dir / f"{technique}_{label}.pdf"

    c = canvas.Canvas(str(out_path), pagesize=letter)
    width, height = letter

    _draw_benign(c, benign_text, width, height)
    _BUILDERS[technique](c, payload, width, height)

    c.save()
    return out_path


def _draw_benign(c: canvas.Canvas, text: str, width: float, height: float) -> None:
    c.setFont("Helvetica", 11)
    c.setFillColor(black)
    y = height - 72
    for line in text.split("\n"):
        c.drawString(72, y, line)
        y -= 16


def _build_whitefont(c: canvas.Canvas, payload: str, width: float, height: float) -> None:
    c.setFont("Helvetica", 10)
    c.setFillColor(white)
    y = 120
    for line in payload.split("\n"):
        c.drawString(72, y, line)
        y -= 14


def _build_tinyfont(c: canvas.Canvas, payload: str, width: float, height: float) -> None:
    c.setFont("Helvetica", 0.5)
    c.setFillColor(black)
    c.drawString(72, 14, payload.replace("\n", " "))


def _build_overlay(c: canvas.Canvas, payload: str, width: float, height: float) -> None:
    c.setFont("Helvetica", 10)
    c.setFillColor(black)
    y = 120
    for line in payload.split("\n"):
        c.drawString(72, y, line)
        y -= 14
    c.setFillColor(white)
    c.rect(60, 80, width - 120, 80, fill=1, stroke=0)


_BUILDERS = {
    "whitefont": _build_whitefont,
    "tinyfont": _build_tinyfont,
    "overlay": _build_overlay,
}
