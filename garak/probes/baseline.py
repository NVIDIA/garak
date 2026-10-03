"""**Intent baseline**

Send intent stubs to a target without applying an attack technique.

Probes in this module establish direct-response baselines for intent scans.
They do not transform or wrap the intent stub.
"""

import garak.probes


class Intent(garak.probes.IntentProbe):
    """Directly test a target against selected intent stubs.

    This probe sends each intent stub unchanged. It measures whether the target
    exhibits the selected behaviour before any additional attack transformation
    is applied.
    """

    active = False
    lang = "*"
    intent = None
    tags = []
    goal = "test whether the target exhibits the selected behaviour"
    tier = garak.probes.Tier.UNLISTED
