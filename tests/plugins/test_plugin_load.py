import pytest
import random

import garak
from garak import _plugins, _config
import garak.buffs.base
import garak.detectors.base
import garak.generators.base
import garak.harnesses.base
import garak.probes.base

PROBES = [classname for (classname, active) in _plugins.enumerate_plugins("probes")]

DETECTORS = [
    classname for (classname, active) in _plugins.enumerate_plugins("detectors")
]

HARNESSES = [
    classname for (classname, active) in _plugins.enumerate_plugins("harnesses")
]

BUFFS = [classname for (classname, active) in _plugins.enumerate_plugins("buffs")]

GENERATORS = [
    "generators.test.Blank"
]  # generator options are complex, hardcode test.Blank only for now


@pytest.fixture
def plugin_configuration(classname):
    category, namespace, klass = classname.split(".")
    plugin_conf = getattr(_config.plugins, category)
    plugin_conf[namespace][klass]["api_key"] = "fake"
    if category == "probes":
        plugin_conf[namespace][klass]["generations"] = random.randint(2, 12)
    if category == "detectors":
        plugin_conf[namespace][klass]["detector_model_config"] = {"api_key": "fake"}
    return (classname, _config)


def ensure_pickle_support(plugin_instance):
    import pickle

    try:
        p = pickle.dumps(plugin_instance)
        l = pickle.loads(p)
    except pickle.PickleError as e:
        assert False, f"Failed to pickle: {e}"
    assert type(plugin_instance) == type(l)


@pytest.mark.parametrize("classname", PROBES)
def test_instantiate_probes(plugin_configuration):
    classname, config_root = plugin_configuration
    try:
        p = _plugins.load_plugin(classname, config_root=config_root)
    except ModuleNotFoundError:
        pytest.skip("required deps not present")
    assert isinstance(p, garak.probes.base.Probe)
    ensure_pickle_support(p)


@pytest.mark.parametrize("classname", DETECTORS)
def test_instantiate_detectors(plugin_configuration):
    classname, config_root = plugin_configuration
    try:
        d = _plugins.load_plugin(classname, config_root=config_root)
    except ModuleNotFoundError:
        pytest.skip("required deps not present")
    assert isinstance(d, garak.detectors.base.Detector)
    ensure_pickle_support(d)


@pytest.mark.parametrize("classname", HARNESSES)
def test_instantiate_harnesses(plugin_configuration):
    classname, config_root = plugin_configuration
    try:
        h = _plugins.load_plugin(classname, config_root=config_root)
    except ModuleNotFoundError:
        pytest.skip("required deps not present")
    assert isinstance(h, garak.harnesses.base.Harness)
    ensure_pickle_support(h)


@pytest.mark.parametrize("classname", BUFFS)
def test_instantiate_buffs(plugin_configuration):
    classname, config_root = plugin_configuration
    try:
        b = _plugins.load_plugin(classname, config_root=config_root)
    except ModuleNotFoundError:
        pytest.skip("required deps not present")
    assert isinstance(b, garak.buffs.base.Buff)
    ensure_pickle_support(b)


@pytest.mark.parametrize("classname", GENERATORS)
def test_instantiate_generators(plugin_configuration):
    classname, config_root = plugin_configuration
    try:
        g = _plugins.load_plugin(classname, config_root=config_root)
    except ModuleNotFoundError:
        pytest.skip("required deps not present")
    assert isinstance(g, garak.generators.base.Generator)
    ensure_pickle_support(g)
