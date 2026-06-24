#!/usr/bin/env python3

# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""assess the quality of intents as configured

indicates problems and improvement possibilities for intents within garak
"""

import sys


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    import argparse
    import garak._config

    garak._config.load_config()
    print(
        f"garak {garak.__description__} v{garak._config.version} ( https://github.com/NVIDIA/garak )"
    )

    p = argparse.ArgumentParser(
        prog="python -m tools.cas.intent_quality",
        description="Run through garak intents and assess how well they're doing",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    p.parse_args(argv)

    import garak.services.intentservice

    garak._config.run.serve_detectorless_intents = True
    garak._config.run.trust_code_stubs = True
    garak.services.intentservice.load()

    import garak.resources.theme as theme

    # go through intents in typology in alpha order

    for intent_code in sorted(garak.services.intentservice.intent_typology.keys()):
        comments = []
        if not garak.services.intentservice.intent_typology[intent_code]["descr"]:
            comments.append("No description")
        if len(intent_code) > 1:
            if not garak.services.intentservice.intent_typology[intent_code].get(
                "default_stub"
            ):
                comments.append("No default stub")
            if garak.services.intentservice.get_detectors(intent_code) is None:
                comments.append("No detectors set")
            stub_count = len(
                garak.services.intentservice.get_intent_stubs(intent_code)
            )
            if stub_count == 0:
                comments.append("No stubs at all")
            elif stub_count == 1:
                comments.append("No supplemental stubs")

        symbol = theme.EMOJI_SCALE_COLOUR_SQUARE[0]
        match len(comments):
            case 0:
                symbol = theme.EMOJI_SCALE_COLOUR_SQUARE[4]
                comments = [" good !"]
            case 1:
                symbol = theme.EMOJI_SCALE_COLOUR_SQUARE[3]
            case 2:
                symbol = theme.EMOJI_SCALE_COLOUR_SQUARE[2]

        print(f"{intent_code:<25} {symbol} {' - '.join(comments)}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
