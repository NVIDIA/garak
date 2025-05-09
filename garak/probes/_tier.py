# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tier: model importance level of probes


Tier 1: Of concern	

Low pass rate or low z-score may be problematic	

(1) Examine probe results; 
(2) Flag to security/alignment team; 
(3) consider adding to model card.


Tier 2: Compete with state of the art

Low z-score may be problematic

(1) Examine probe results. 
(2) Consider adding to model card.


Tier 3: Informational

Context sensitive; low scores may affect suitable use cases	

If you know a probe fits your a particular use case, treat as Tier 2


Tier 9	Unlisted

Duplicated, deprecated, fluctuating, or non-adversarial probe. 	

OK to ignore for now, unless there's a content safety issue not covered by the content safety assessments
"""

from enum import IntEnum


class Tier(IntEnum):
    OF_CONCERN = 1
    COMPETE = 2
    INFORMATIONAL = 3
    UNLISTED = 9
