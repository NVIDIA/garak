# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from garak.configurable import Configurable
from garak._config import GarakSubConfig


@pytest.fixture
def generator_sub_config():
    config = GarakSubConfig()
    generators = {
        "mock": {
            "constructor_param": "from_config",
            "defaulted_constructor_param": "from_config",
            "no_constructor_param": "from_config",
        }
    }
    setattr(config, "generators", generators)
    return config


class mockConfigurable(Configurable):
    # Configurable is coupled to hierarchy of plugin types
    __module__ = "garak.generators.mock"

    DEFAULT_PARAMS = {
        "class_var": "from_class",
        "class_dict_var": {
            "dict_a": "dict_val",
            "dict_b": "dict_val",
        },
    }

    _system_params = {"enable_experimental"}  # global default `False`
    _run_params = {"generations"}  # global default `5`

    def __init__(
        self,
        constructor_param=None,
        defaulted_constructor_param=None,
        config_root=GarakSubConfig(),
    ):
        self.constructor_param = constructor_param
        self.defaulted_constructor_param = defaulted_constructor_param
        self._load_config(config_root)


# when a parameter is provided in config_root set on the resulting object
def test_config_root_only(generator_sub_config):
    m = mockConfigurable(config_root=generator_sub_config)
    for k, v in generator_sub_config.generators["mock"].items():
        assert getattr(m, k) == v


# when a parameter is provided in config_root by `module.classname` set on the resulting object
def test_config_root_module_classname(generator_sub_config):
    module_config = generator_sub_config.generators.pop("mock")
    generator_sub_config.generators["mock.mockConfigurable"] = module_config
    m = mockConfigurable(config_root=generator_sub_config)
    for k, v in generator_sub_config.generators["mock.mockConfigurable"].items():
        assert getattr(m, k) == v


# when a parameter is provided in config_root as a dict set on the resulting object
def test_config_root_as_dict(generator_sub_config):
    config = {"generators": generator_sub_config.generators}
    m = mockConfigurable(config_root=config)
    for k, v in config["generators"]["mock"].items():
        assert getattr(m, k) == v


# when a parameter is set in the same parameter name in the constructor will not be overridden by config
def test_param_provided(generator_sub_config):
    passed_param = "from_caller"
    m = mockConfigurable(passed_param, config_root=generator_sub_config)
    assert m.constructor_param == passed_param


# when a run or system parameter exists on the class it is set from global config if not provided
def test_run_vars_propagate_to_instance(generator_sub_config):
    from garak import _config

    _config.load_base_config()

    m = mockConfigurable(config_root=generator_sub_config)
    for p in m._system_params:
        assert getattr(m, p) == getattr(_config.system, p)
    for p in m._run_params:
        assert getattr(m, p) == getattr(_config.run, p)


# when a run or system parameter is provided in plugin map hold hold it first
def test_class_over_run_vars_propagate_to_instance(generator_sub_config):
    from garak import _config
    import random

    _config.load_base_config()

    override_values = {}
    for p in mockConfigurable._system_params.union(mockConfigurable._run_params):
        override_values[p] = random.randint(100, 500)
        generator_sub_config.generators["mock"][p] = override_values[p]

    m = mockConfigurable(config_root=generator_sub_config)
    for p in m._system_params:
        assert getattr(m, p) == override_values[p]
    for p in m._run_params:
        assert getattr(m, p) == override_values[p]


# when a default parameter is provided and not config_root set on the resulting object
def test_class_vars_propagate_to_instance(generator_sub_config):
    m = mockConfigurable(config_root=generator_sub_config)
    assert m.class_var == m.DEFAULT_PARAMS["class_var"]
    assert m.class_dict_var == m.DEFAULT_PARAMS["class_dict_var"]


# when a default parameter dictionary is provided merge on the resulting object
def test_class_dict_merge_to_instance(generator_sub_config):
    config_dict_var = {"dict_a": "test_val", "dict_c": "test_val"}
    generator_sub_config.generators["mock"]["class_dict_var"] = config_dict_var
    m = mockConfigurable(config_root=generator_sub_config)
    assert m.class_dict_var == m.DEFAULT_PARAMS["class_dict_var"] | config_dict_var
    assert m.class_dict_var["dict_a"] == config_dict_var["dict_a"]
    assert m.class_dict_var["dict_c"] == config_dict_var["dict_c"]


# when a default parameter is provided and not config_root set on the resulting object
def test_config_mask_class_vars_to_instance(generator_sub_config):
    generator_sub_config.generators["mock"]["class_var"] = "from_config"
    m = mockConfigurable(config_root=generator_sub_config)
    assert m.class_var == "from_config"


# when `_supported_params` exist unknown params are rejected
def test_config_supported_params(generator_sub_config):
    class mock_supported(mockConfigurable):
        __module__ = "garak.generators.mock"

        _supported_params = ("constructor_param", "defaulted_constructor_param")

    m = mock_supported(config_root=generator_sub_config)
    for k, v in generator_sub_config.generators["mock"].items():
        if k in mock_supported._supported_params:
            assert getattr(m, k) == v
        else:
            assert hasattr(m, k) is False
