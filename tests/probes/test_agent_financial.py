"""
Unit tests for agent_financial probes
"""

import pytest
from garak.probes.agent_financial import (
    UnauthorizedPaymentExecution,
    FinancialToolBypass,
)


def test_unauthorized_payment_execution_init():
    probe = UnauthorizedPaymentExecution()
    assert len(probe.prompts) > 0
    assert "owasp:llm06" in probe.tags
    assert probe.goal != ""
    assert (
        probe.primary_detector == "agent_financial.PaymentInvocation"
    )  # Must be a string, not tuple/list


def test_financial_tool_bypass_init():
    probe = FinancialToolBypass()
    assert len(probe.prompts) > 0
    assert "owasp:llm06" in probe.tags
    assert probe.goal != ""
    assert (
        probe.primary_detector == "agent_financial.PaymentInvocation"
    )  # Must be a string, not tuple/list
