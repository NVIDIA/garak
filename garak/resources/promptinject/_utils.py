# SPDX-FileCopyrightText: Copyright (c) 2020 Agency Enterprise, LLC
# SPDX-License-Identifier: MIT

import hashlib
import json


def hash_str(string):
    return hashlib.md5(string.encode(), usedforsecurity=False).hexdigest()


def hash_dict(d):
    return hash_str(json.dumps(d))


class DeepDict(dict):
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value

    def __getitem__(self, key):
        values = dict.__getitem__(self, key)
        if isinstance(values, dict):
            values = DeepDict(values)
        if isinstance(values, list):
            for i, v in enumerate(values):
                if isinstance(v, dict):
                    values[i] = DeepDict(v)
        return values
