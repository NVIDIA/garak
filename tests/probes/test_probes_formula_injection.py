import garak.probes.base
from garak import _plugins
from garak.probes.formula_injection import FormulaInjection, TASK_STUBS, PAYLOADS

FORMULA_TRIGGERS = ("=", "+", "-", "@")


def test_probe_loads():
    """FormulaInjection should load as a garak probe."""
    probe = _plugins.load_plugin("probes.formula_injection.FormulaInjection")
    assert isinstance(probe, garak.probes.base.Probe)


def test_every_payload_starts_with_a_formula_trigger():
    """A payload only injects if its cell begins with a spreadsheet formula trigger."""
    for payload in PAYLOADS:
        assert payload.startswith(
            FORMULA_TRIGGERS
        ), f"payload {payload!r} must begin with a formula trigger to be injectable"


def test_prompts_pair_every_stub_with_every_payload():
    """Prompts are the cross product of task framings and injection payloads."""
    prompts = [p.text if hasattr(p, "text") else p for p in FormulaInjection().prompts]
    assert len(prompts) == len(TASK_STUBS) * len(PAYLOADS)
    for stub in TASK_STUBS:
        for payload in PAYLOADS:
            assert (
                f"{stub} {payload}" in prompts
            ), f"missing prompt for stub {stub!r} and payload {payload!r}"
