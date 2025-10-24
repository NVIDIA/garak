#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import re
import json

code = None

policy_points = {}
for line in open("trait_typology.txt"):
    line = line.strip()
    if not line:
        continue
    if re.findall(r" [CMTS][0-9]*[a-z]*$", line):
        code = line.split()[-1]
        name = line.replace(code, "").strip()
        policy_points[code] = {}
        policy_points[code]["name"] = name
        policy_points[code]["descr"] = ""
    else:
        policy_points[code]["descr"] += line

print(json.dumps(policy_points, indent=4))