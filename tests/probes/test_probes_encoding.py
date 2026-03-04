# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest
import garak.probes.encoding
from garak import _plugins

ENCODING_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.encoding")
]

# Probes known to include the trigger in final prompts
CLEAR_TRIGGER_PROBES = [
    "probes.encoding.InjectMime",
    "probes.encoding.InjectQP",
]


@pytest.mark.parametrize("classname", ENCODING_PROBES)
def test_encoding_len_cap(classname):
    p = _plugins.load_plugin(classname)
    num_payloads = len(p._payloads)
    num_templates = len(garak.probes.encoding.TEMPLATES)
    num_encoders = len(p.encoding_funcs)
    # prompts are a unique set and some functions may generate duplicate, hence "<=" test
    assert len(p.prompts) <= num_payloads * num_templates * num_encoders


@pytest.mark.parametrize("classname", ENCODING_PROBES)
def test_encoding_prompt_trigger_match(classname):
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) == len(p.triggers)


@pytest.mark.parametrize(
    "classname",
    [classname for classname in ENCODING_PROBES if not CLEAR_TRIGGER_PROBES],
)
def test_encoding_triggers_not_in_prompts(classname):
    p = _plugins.load_plugin(classname)
    for i in range(len(p.triggers)):
        assert p.triggers[i] not in p.prompts[i]


@pytest.mark.parametrize("classname", ENCODING_PROBES)
def test_encoding_prompt_cap(classname):
    import random
    from garak import _config

    rand_cap = random.randint(1, 20)
    _config.run.soft_probe_prompt_cap = rand_cap
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) <= rand_cap


@pytest.mark.parametrize("classname", ENCODING_PROBES)
def test_encoding_suppress_prompt_cap(classname):
    import random
    from garak import _config

    rand_cap = random.randint(1, 5)
    _config.run.soft_probe_prompt_cap = rand_cap
    instance_config = {
        "probes": {
            "encoding": {
                classname.split(".")[-1]: {
                    "follow_prompt_cap": False,
                }
            }
        }
    }
    p = _plugins.load_plugin(classname, config_root=instance_config)
    assert len(p.prompts) >= rand_cap
