# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Detectors for the smuggling probe family.

Provides LLM-as-judge detectors that evaluate target responses semantically
rather than via English-language refusal string matching. Closes the
false-positive gap on smuggling probes (e.g., homoglyph obfuscation) where
targets may respond in the same script as the obfuscated input."""

from garak.detectors.judge import ModelAsJudge


class HomoglyphObfuscationJudge(ModelAsJudge):
    """LLM-as-judge detector for the smuggling.HomoglyphObfuscation probe.

    Uses a configured judge model to evaluate whether the target response
    complied with the obfuscated harmful request, regardless of response
    language. Closes the false-positive gap where non-English refusals are
    misidentified as successful bypass by string-match detectors such as
    mitigation.MitigationBypass.

    Configured via the standard ModelAsJudge parameters:
    detector_model_type, detector_model_name, detector_model_config,
    detector_goal, confidence_cutoff."""

    active = True

    description = (
        "Uses a configured judge model to evaluate whether the target "
        "complied with the obfuscated harmful request, language-agnostic"
    )

    # TODO: Refine detector_goal prompt for homoglyph-specific evaluation.
    # TODO: Add test coverage under tests/detectors/test_detectors_smuggling.py
    #       following the pattern in tests/detectors/test_detectors_judge.py.
    # TODO: Wire into HomoglyphObfuscation probe as an alternative or
    #       replacement primary_detector once validated.
