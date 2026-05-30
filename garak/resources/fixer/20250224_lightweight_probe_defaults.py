# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.resources.fixer import Migration
from garak.resources.fixer import _plugin


class RenameFigstep(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename FigStep probes to make lightweight the default"""

        path = ["plugins", "probes", "visual_jailbreak"]
        renames = (
            ["FigStep", "FigStepFull"],
            ["FigStepTiny", "FigStep"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameGraphConn(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename snowball.graphconnectivity probes to make lightweight the default"""

        path = ["plugins", "probes", "snowball"]
        renames = (
            ["GraphConnectivity", "GraphConnectivityFull"],
            ["GraphConnectivityMini", "GraphConnectivity"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenamePrimes(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename snowball.primes probes to make lightweight the default"""

        path = ["plugins", "probes", "snowball"]
        renames = (
            ["Primes", "PrimesFull"],
            ["PrimesMini", "Primes"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameSenators(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename snowball.senators probes to make lightweight the default"""

        path = ["plugins", "probes", "snowball"]
        renames = (
            ["Senators", "SenatorsFull"],
            ["SenatorsMini", "Senators"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameHijackHateHumans(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename promptinject.HijackHateHumans probes to make lightweight the default"""

        path = ["plugins", "probes", "promptinject"]
        renames = (
            ["HijackHateHumans", "HijackHateHumansFull"],
            ["HijackHateHumansMini", "HijackHateHumans"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameHijackKillHumans(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename promptinject.HijackKillHumans probes to make lightweight the default"""

        path = ["plugins", "probes", "promptinject"]
        old = "HijackKillHumans"
        new = "HijackKillHumansFull"
        renames = (
            ["HijackKillHumans", "HijackKillHumansFull"],
            ["HijackKillHumansMini", "HijackKillHumans"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameHijackLongPrompt(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename promptinject.HijackKillHumans probes to make lightweight the default"""

        path = ["plugins", "probes", "promptinject"]
        renames = (
            ["HijackLongPrompt", "HijackLongPromptFull"],
            ["HijackLongPromptMini", "HijackLongPrompt"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenamePastTense(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename phrasing.PastTense probes to make lightweight the default"""

        path = ["plugins", "probes", "phrasing"]
        renames = (
            ["PastTense", "PastTenseFull"],
            ["PastTenseMini", "PastTense"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameFutureTense(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename phrasing.FutureTense probes to make lightweight the default"""

        path = ["plugins", "probes", "phrasing"]
        renames = (
            ["FutureTense", "FutureTenseFull"],
            ["FutureTenseMini", "FutureTense"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameLiteratureCloze(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename leakreplay.LiteratureCloze probes to make lightweight the default"""

        path = ["plugins", "probes", "leakreplay"]
        renames = (
            ["LiteratureCloze", "LiteratureClozeFull"],
            ["LiteratureCloze80", "LiteratureCloze"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameLiteratureComplete(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename leakreplay.LiteratureComplete probes to make lightweight the default"""

        path = ["plugins", "probes", "leakreplay"]
        renames = (
            ["LiteratureComplete", "LiteratureCompleteFull"],
            ["LiteratureComplete80", "LiteratureComplete"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameLatentJailbreak(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename latentinjection.LatentJailbreak probes to make lightweight the default"""

        path = ["plugins", "probes", "latentinjection"]

        renames = (
            ["LatentJailbreak", "LatentJailbreakFull"],
            ["LatentJailbreakMini", "LatentJailbreak"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameLatentInjectionFactSnippetEiffel(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename latentinjection.LatentInjectionFactSnippetEiffel probes to make lightweight the default"""

        path = ["plugins", "probes", "latentinjection"]

        renames = (
            [
                "LatentInjectionFactSnippetEiffel",
                "LatentInjectionFactSnippetEiffelFull",
            ],
            [
                "LatentInjectionFactSnippetEiffelMini",
                "LatentInjectionFactSnippetEiffel",
            ],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameDanInTheWild(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename dan.DanInTheWild probes to make lightweight the default"""

        path = ["plugins", "probes", "dan"]
        renames = (
            ["DanInTheWild", "DanInTheWildFull"],
            ["DanInTheWildMini", "DanInTheWild"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameContinueSlursReclaimedSlurs(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename continuation.ContinueSlursReclaimedSlurs probes to make lightweight the default"""

        path = ["plugins", "probes", "continuation"]
        renames = (
            ["ContinueSlursReclaimedSlurs", "ContinueSlursReclaimedSlursFull"],
            ["ContinueSlursReclaimedSlursMini", "ContinueSlursReclaimedSlurs"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config


class RenameFalseAssertion(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename misleadeing.FalseAssertion probes to make lightweight the default"""

        path = ["plugins", "probes", "misleading"]
        old = "FalseAssertion50"
        new = "FalseAssertion"
        return _plugin.rename(config_dict, path, old, new)


class RenameGlitch(Migration):
    def apply(config_dict: dict) -> dict:
        """Rename glitch probes to make lightweight the default"""

        path = ["plugins", "probes", "glitch"]

        renames = (
            ["Glitch", "GlitchFull"],
            ["Glitch100", "Glitch"],
        )
        updated_config = config_dict
        for old, new in renames:
            updated_config = _plugin.rename(updated_config, path, old, new)
        return updated_config
