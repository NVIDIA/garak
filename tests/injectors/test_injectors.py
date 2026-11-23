# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the injector plugin category and its base class."""

import pytest

import garak._plugins
from garak import _config
from garak.exception import InvalidInjectionPlanError
from garak.injection import (
    Coverage,
    Delivery,
    InjectionBinding,
    InjectionEvidence,
    InjectionPlan,
    SurfaceDescriptor,
)
from garak.injectors.base import Injector


class RecordingInjector(Injector):
    """Concrete injector capturing arm and disarm state."""

    capabilities = ["test_channel"]
    DEFAULT_PARAMS = {"host": None}

    def arm(self, payload):
        self.armed_payload = payload
        return {"capability": "test_channel", "host": self.host}

    def disarm(self):
        self.armed_payload = None


def test_injectors_are_a_plugin_category():
    # enumerate_plugins raises ValueError for unknown categories
    plugins = garak._plugins.enumerate_plugins("injectors")
    assert isinstance(plugins, list)
    # the base class is not offered as a loadable plugin
    assert ("injectors.base.Injector", True) not in plugins


def test_base_injector_has_plugin_info():
    info = garak._plugins.plugin_info("injectors.base.Injector")
    assert isinstance(info, dict)
    assert info.get("description"), "base injector must carry a description"


def test_base_injector_is_loadable():
    injector = garak._plugins.load_plugin("injectors.base.Injector")
    assert isinstance(injector, Injector)


def test_arm_disarm_lifecycle():
    injector = RecordingInjector()
    descriptor = injector.arm("payload text")
    assert injector.armed_payload == "payload text"
    assert descriptor == {"capability": "test_channel", "host": None}
    injector.disarm()
    assert injector.armed_payload is None


def test_base_arm_and_disarm_are_not_implemented():
    injector = Injector()
    with pytest.raises(NotImplementedError):
        injector.arm("payload")
    with pytest.raises(NotImplementedError):
        injector.disarm()


def test_injector_config_root_node():
    # the plugins config tree carries an injectors root node like other plugin types
    assert hasattr(_config.plugins, "injectors")


def test_load_plugin_caches_injector_instances():
    """The plugin provider hands out one instance per spec and config.

    Injectors are cached like every other plugin, so any per-execution state
    they keep is shared between the probes that load them.
    """
    config_root = {"injectors": {"mimcp": {"MiMCPInjector": {"host": None}}}}
    first = garak._plugins.load_plugin(
        "injectors.mimcp.MiMCPInjector", config_root=config_root
    )
    second = garak._plugins.load_plugin(
        "injectors.mimcp.MiMCPInjector", config_root=config_root
    )
    assert first is second, "load_plugin must return the cached injector instance"


# ── binding lifecycle ──────────────────────────────────────────────────────────


class FakeBinding(InjectionBinding):
    """Test binding owning one session per execution."""

    def __init__(self, execution_id):
        super().__init__()
        self.execution_id = execution_id
        self.session = f"session-{execution_id}"
        self.close_count = 0

    def collect_evidence(self):
        return InjectionEvidence(
            execution_id=self.execution_id,
            delivery=Delivery(delivered=True),
            coverage=Coverage(errors=tuple(self.coverage_errors)),
        )

    def _close(self):
        self.close_count += 1
        self.session = None


class BindingInjector(Injector):
    """Test injector handing out independent bindings."""

    surface_kinds = frozenset({"test.surface"})
    DEFAULT_PARAMS = {"host": None}

    def bind(self, plan, surface, execution_id):
        return FakeBinding(execution_id)


def _plan(name="surf"):
    return InjectionPlan(surface_kind="test.surface", surface_name=name)


def _surface(name="surf"):
    return SurfaceDescriptor(kind="test.surface", name=name)


def test_validate_rejects_foreign_surface_kinds():
    injector = BindingInjector()
    plan = InjectionPlan(surface_kind="other.surface", surface_name="surf")
    with pytest.raises(InvalidInjectionPlanError, match="other.surface"):
        injector.validate(plan, _surface())


def test_validate_rejects_mismatched_surfaces():
    injector = BindingInjector()
    with pytest.raises(InvalidInjectionPlanError, match="targets"):
        injector.validate(_plan("surf"), _surface("other"))


def test_validate_accepts_a_matching_plan():
    injector = BindingInjector()
    injector.validate(_plan(), _surface())


def test_two_bindings_keep_separate_sessions():
    """One injector instance serves parallel executions independently."""
    injector = BindingInjector()
    first = injector.bind(_plan(), _surface(), "exec-1")
    second = injector.bind(_plan(), _surface(), "exec-2")

    assert first.session == "session-exec-1"
    assert second.session == "session-exec-2"

    first.close()
    assert (
        second.session == "session-exec-2"
    ), "closing one binding must not touch another"
    assert (
        first.collect_evidence().execution_id == "exec-1"
    ), "a closed binding still reports its own evidence"


def test_close_runs_after_a_generator_exception():
    """The context manager releases the surface even when the body raises."""
    injector = BindingInjector()
    binding = injector.bind(_plan(), _surface(), "exec-1")

    with pytest.raises(RuntimeError):
        with binding:
            raise RuntimeError("generator blew up")

    assert binding.close_count == 1
    assert binding.session is None


def test_second_close_does_nothing():
    injector = BindingInjector()
    binding = injector.bind(_plan(), _surface(), "exec-1")

    binding.close()
    binding.close()

    assert binding.close_count == 1, "close must be idempotent"


def test_base_binding_collect_evidence_is_not_implemented():
    with pytest.raises(NotImplementedError):
        InjectionBinding().collect_evidence()
