# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the budget tracking and cost control module."""

import pytest
from dataclasses import asdict

from garak.budget import TokenUsage, CostInfo, BudgetManager
from garak.exception import BudgetExceededError


class TestTokenUsage:
    """Tests for TokenUsage dataclass."""

    def test_basic_creation(self):
        """Test basic TokenUsage creation."""
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            model="gpt-4o",
        )
        assert usage.prompt_tokens == 100
        assert usage.completion_tokens == 50
        assert usage.total_tokens == 150
        assert usage.model == "gpt-4o"
        assert usage.estimated is False

    def test_auto_calculate_total(self):
        """Test that total_tokens is auto-calculated if not provided."""
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            model="gpt-4o",
        )
        assert usage.total_tokens == 150

    def test_estimated_flag(self):
        """Test the estimated flag for character-based estimates."""
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            model="test-model",
            estimated=True,
        )
        assert usage.estimated is True

    def test_timestamp_auto_generated(self):
        """Test that timestamp is auto-generated."""
        usage = TokenUsage(prompt_tokens=10, completion_tokens=5)
        assert usage.timestamp is not None
        assert len(usage.timestamp) > 0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            model="gpt-4o",
            estimated=False,
        )
        d = asdict(usage)
        assert d["prompt_tokens"] == 100
        assert d["completion_tokens"] == 50
        assert d["model"] == "gpt-4o"


class TestCostInfo:
    """Tests for CostInfo dataclass."""

    def test_basic_creation(self):
        """Test basic CostInfo creation."""
        cost = CostInfo(
            input_cost=0.01,
            output_cost=0.02,
            total_cost=0.03,
        )
        assert cost.input_cost == 0.01
        assert cost.output_cost == 0.02
        assert cost.total_cost == 0.03
        assert cost.currency == "USD"

    def test_auto_calculate_total(self):
        """Test that total_cost is auto-calculated if not provided."""
        cost = CostInfo(input_cost=0.01, output_cost=0.02)
        assert cost.total_cost == pytest.approx(0.03)


class TestBudgetManager:
    """Tests for BudgetManager class."""

    def test_init_no_limits(self):
        """Test initialization without limits."""
        manager = BudgetManager()
        assert manager.cost_limit is None
        assert manager.token_limit is None
        assert manager.total_tokens == 0
        assert manager.total_cost == 0.0

    def test_init_with_limits(self):
        """Test initialization with limits."""
        manager = BudgetManager(cost_limit=10.0, token_limit=100000)
        assert manager.cost_limit == 10.0
        assert manager.token_limit == 100000

    def test_init_rejects_negative_cost_limit(self):
        """Test that negative cost_limit raises ValueError."""
        with pytest.raises(ValueError, match="cost_limit must be positive"):
            BudgetManager(cost_limit=-1.0)

    def test_init_rejects_zero_cost_limit(self):
        """Test that zero cost_limit raises ValueError."""
        with pytest.raises(ValueError, match="cost_limit must be positive"):
            BudgetManager(cost_limit=0)

    def test_init_rejects_negative_token_limit(self):
        """Test that negative token_limit raises ValueError."""
        with pytest.raises(ValueError, match="token_limit must be positive"):
            BudgetManager(token_limit=-100)

    def test_init_rejects_zero_token_limit(self):
        """Test that zero token_limit raises ValueError."""
        with pytest.raises(ValueError, match="token_limit must be positive"):
            BudgetManager(token_limit=0)

    def test_record_usage_updates_totals(self):
        """Test that recording usage updates running totals."""
        manager = BudgetManager()

        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            model="gpt-4o",
        )
        manager.record_usage(usage)

        assert manager.total_prompt_tokens == 100
        assert manager.total_completion_tokens == 50
        assert manager.total_tokens == 150
        assert len(manager.usage_log) == 1

    def test_record_multiple_usages(self):
        """Test recording multiple usage entries."""
        manager = BudgetManager()

        for i in range(3):
            usage = TokenUsage(
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
                model="gpt-4o",
            )
            manager.record_usage(usage)

        assert manager.total_prompt_tokens == 300
        assert manager.total_completion_tokens == 150
        assert manager.total_tokens == 450
        assert len(manager.usage_log) == 3

    def test_token_limit_exceeded(self):
        """Test that BudgetExceededError is raised when token limit exceeded."""
        manager = BudgetManager(token_limit=100)

        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            model="gpt-4o",
        )

        with pytest.raises(BudgetExceededError) as exc_info:
            manager.record_usage(usage)

        assert "Token limit exceeded" in str(exc_info.value)
        assert "150" in str(exc_info.value)
        assert "100" in str(exc_info.value)

    def test_cost_limit_exceeded(self):
        """Test that BudgetExceededError is raised when cost limit exceeded."""
        manager = BudgetManager(cost_limit=0.001)  # Very low limit

        # gpt-4o is $2.50/1M input, $10/1M output
        # 1000 tokens = $0.0025 input + $0.01 output = $0.0125
        usage = TokenUsage(
            prompt_tokens=1000,
            completion_tokens=1000,
            total_tokens=2000,
            model="gpt-4o",
        )

        with pytest.raises(BudgetExceededError) as exc_info:
            manager.record_usage(usage)

        assert "Cost limit exceeded" in str(exc_info.value)

    def test_check_budget_within_limits(self):
        """Test check_budget returns True when within limits."""
        manager = BudgetManager(cost_limit=100.0, token_limit=1000000)

        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            model="gpt-4o",
        )
        manager.record_usage(usage)

        assert manager.check_budget() is True

    def test_calculate_cost_known_model(self):
        """Test cost calculation for a known model."""
        manager = BudgetManager()

        usage = TokenUsage(
            prompt_tokens=1000000,  # 1M tokens
            completion_tokens=1000000,
            model="gpt-4o",
        )

        cost = manager.calculate_cost(usage)

        # gpt-4o: $2.50/1M input, $10/1M output
        assert cost.input_cost == pytest.approx(2.50)
        assert cost.output_cost == pytest.approx(10.00)
        assert cost.total_cost == pytest.approx(12.50)

    def test_calculate_cost_unknown_model_uses_defaults(self):
        """Test that unknown models use default pricing."""
        manager = BudgetManager()

        usage = TokenUsage(
            prompt_tokens=1000000,
            completion_tokens=1000000,
            model="unknown-model-xyz",
        )

        cost = manager.calculate_cost(usage)

        # Should use defaults: $5/1M input, $15/1M output
        assert cost.input_cost == pytest.approx(5.00)
        assert cost.output_cost == pytest.approx(15.00)

    def test_estimate_tokens(self):
        """Test character-based token estimation."""
        manager = BudgetManager()

        # Default is 4 chars per token
        text = "This is a test string with 48 characters in it!!"
        estimated = manager.estimate_tokens(text)

        assert estimated == len(text) // 4

    def test_estimate_usage(self):
        """Test creating estimated TokenUsage from text."""
        manager = BudgetManager()

        prompt = "Hello, how are you?"  # 19 chars = 4 tokens
        completion = "I am fine, thank you!"  # 21 chars = 5 tokens

        usage = manager.estimate_usage(prompt, completion, "test-model")

        assert usage.estimated is True
        assert usage.model == "test-model"
        assert usage.prompt_tokens > 0
        assert usage.completion_tokens > 0

    def test_get_summary(self):
        """Test getting usage summary."""
        manager = BudgetManager(cost_limit=100.0, token_limit=1000000)

        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            model="gpt-4o",
        )
        manager.record_usage(usage)

        summary = manager.get_summary()

        assert summary["total_prompt_tokens"] == 100
        assert summary["total_completion_tokens"] == 50
        assert summary["total_tokens"] == 150
        assert summary["api_calls"] == 1
        assert summary["cost_limit"] == 100.0
        assert summary["token_limit"] == 1000000
        assert "gpt-4o" in summary["models_used"]

    def test_format_summary(self):
        """Test formatted summary output."""
        manager = BudgetManager()

        usage = TokenUsage(
            prompt_tokens=1000,
            completion_tokens=500,
            model="gpt-4o",
        )
        manager.record_usage(usage)

        formatted = manager.format_summary()

        assert "Token Usage Summary" in formatted
        assert "1,500" in formatted  # Total tokens
        assert "gpt-4o" in formatted

    def test_multiple_models_tracked(self):
        """Test tracking usage across multiple models."""
        manager = BudgetManager()

        models = ["gpt-4o", "gpt-3.5-turbo", "claude-3-sonnet"]
        for model in models:
            usage = TokenUsage(
                prompt_tokens=100,
                completion_tokens=50,
                model=model,
            )
            manager.record_usage(usage)

        summary = manager.get_summary()
        assert len(summary["models_used"]) == 3


class TestPreFlightBudgetCheck:
    """Tests for pre-flight budget checking in parallel execution."""

    def test_can_proceed_when_within_limits(self):
        """Test can_proceed returns True when within limits."""
        manager = BudgetManager(token_limit=1000, cost_limit=1.0)
        manager.init_shared_state()

        assert manager.can_proceed() is True

    def test_can_proceed_false_when_token_limit_reached(self):
        """Test can_proceed returns False when token limit reached."""
        manager = BudgetManager(token_limit=100)
        manager.init_shared_state()

        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            model="gpt-4o",
        )

        with pytest.raises(BudgetExceededError):
            manager.record_usage(usage)

        # After exception, can_proceed should return False
        assert manager.can_proceed() is False

    def test_can_proceed_false_when_cost_limit_reached(self):
        """Test can_proceed returns False when cost limit reached."""
        manager = BudgetManager(cost_limit=0.001)
        manager.init_shared_state()

        usage = TokenUsage(
            prompt_tokens=1000,
            completion_tokens=1000,
            total_tokens=2000,
            model="gpt-4o",
        )

        with pytest.raises(BudgetExceededError):
            manager.record_usage(usage)

        # After exception, can_proceed should return False
        assert manager.can_proceed() is False

    def test_shared_state_marks_budget_exceeded(self):
        """Test that check_budget marks shared state when exceeded."""
        from garak.budget import is_budget_exceeded, init_shared_budget_state

        init_shared_budget_state(token_limit=100, cost_limit=None)
        manager = BudgetManager(token_limit=100)

        usage = TokenUsage(
            prompt_tokens=150,
            completion_tokens=0,
            total_tokens=150,
            model="gpt-4o",
        )

        with pytest.raises(BudgetExceededError):
            manager.record_usage(usage)

        # Shared state should be marked
        assert is_budget_exceeded() is True

    def test_is_budget_exceeded_without_init(self):
        """Test is_budget_exceeded returns False when not initialized."""
        from garak import budget

        # Reset shared state
        budget._shared_budget_exceeded = None

        assert budget.is_budget_exceeded() is False


class TestBudgetIntegration:
    """Integration tests for budget tracking with mocked generator."""

    def test_usage_attached_to_message_notes(self):
        """Test that usage data is properly attached to Message notes."""
        from garak.attempt import Message

        # Simulate what the generator does
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            model="test-model",
        )

        message = Message(text="Test response")
        message.notes = {"token_usage": asdict(usage)}

        assert "token_usage" in message.notes
        assert message.notes["token_usage"]["prompt_tokens"] == 100
        assert message.notes["token_usage"]["completion_tokens"] == 50


class TestFullBudgetWorkflow:
    """Integration tests for the full budget workflow.

    These tests verify the complete budget tracking path:
    config -> BudgetManager -> init_shared_state -> worker cost calculation -> budget enforcement
    """

    def test_model_pricing_passed_to_workers(self):
        """Test that model pricing is correctly passed to worker processes."""
        from garak.budget import (
            init_shared_budget_state,
            get_model_pricing,
            get_budget_limits,
        )
        from garak import budget

        # Reset shared state
        budget._model_pricing = None

        # Initialize with known model pricing
        init_shared_budget_state(
            token_limit=10000,
            cost_limit=1.0,
            model_pricing=(2.50, 10.00),  # GPT-4o pricing
        )

        # Verify pricing is retrievable (simulates worker process)
        input_price, output_price = get_model_pricing()
        assert input_price == 2.50
        assert output_price == 10.00

        # Verify limits are also available
        token_limit, cost_limit = get_budget_limits()
        assert token_limit == 10000
        assert cost_limit == 1.0

    def test_budget_manager_passes_model_pricing(self):
        """Test BudgetManager.init_shared_state passes model pricing correctly."""
        from garak.budget import get_model_pricing
        from garak import budget

        # Reset shared state
        budget._model_pricing = None

        manager = BudgetManager(token_limit=10000, cost_limit=1.0)
        # Pass a known model name
        manager.init_shared_state(model="gpt-4o")

        # Get the pricing that would be used by workers
        input_price, output_price = get_model_pricing()

        # gpt-4o pricing from model_pricing.yaml: input=2.50, output=10.00
        assert input_price == 2.50
        assert output_price == 10.00

    def test_default_pricing_when_model_unknown(self):
        """Test that default pricing is used when model is not found."""
        from garak.budget import get_model_pricing
        from garak import budget

        # Reset shared state
        budget._model_pricing = None

        manager = BudgetManager(token_limit=10000)
        # Pass an unknown model name
        manager.init_shared_state(model="totally-unknown-model-xyz")

        input_price, output_price = get_model_pricing()

        # Should get default pricing from model_pricing.yaml
        # default_input_price: 5.00, default_output_price: 15.00
        assert input_price == 5.00
        assert output_price == 15.00

    def test_cost_calculation_accuracy(self):
        """Test that cost calculation in workers matches BudgetManager calculation."""
        from garak.budget import get_model_pricing, init_shared_budget_state
        from garak import budget

        # Reset shared state
        budget._model_pricing = None

        # Set up with known pricing
        init_shared_budget_state(
            token_limit=None,
            cost_limit=10.0,
            model_pricing=(2.50, 10.00),  # $2.50/1M input, $10.00/1M output
        )

        # Simulate usage
        prompt_tokens = 1000
        completion_tokens = 500

        # Calculate cost as worker would
        input_price, output_price = get_model_pricing()
        worker_cost_usd = (
            (prompt_tokens / 1_000_000) * input_price +
            (completion_tokens / 1_000_000) * output_price
        )

        # Calculate cost as BudgetManager would
        manager = BudgetManager()
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            model="gpt-4o",
        )
        cost_info = manager.calculate_cost(usage)

        # They should match (or be very close due to floating point)
        assert abs(worker_cost_usd - cost_info.total_cost) < 0.0001

    def test_budget_exceeded_flag_propagation(self):
        """Test that budget exceeded flag properly propagates across processes."""
        from garak.budget import (
            init_shared_budget_state,
            is_budget_exceeded,
            mark_budget_exceeded,
            update_shared_usage,
            get_shared_usage,
        )
        from garak import budget

        # Reset shared state
        budget._shared_budget_exceeded = None

        # Initialize with tight limits
        init_shared_budget_state(
            token_limit=100,
            cost_limit=0.01,
            model_pricing=(10.00, 30.00),  # Expensive model
        )

        # Initially not exceeded
        assert is_budget_exceeded() is False

        # Simulate worker updating usage
        update_shared_usage(
            tokens=50,
            cost_cents=5,  # $0.05
            prompt_tokens=30,
            completion_tokens=20,
        )

        # Check shared usage
        total_tokens, total_cost, api_calls, prompt, completion = get_shared_usage()
        assert total_tokens == 50
        assert prompt == 30
        assert completion == 20

        # Mark as exceeded (simulates worker detecting limit breach)
        mark_budget_exceeded()

        # Flag should now be True
        assert is_budget_exceeded() is True

    def test_pool_initializer_includes_pricing(self):
        """Test that pool initializer args include model pricing."""
        from garak.budget import (
            init_shared_budget_state,
            get_pool_initializer,
        )
        from garak import budget

        # Reset shared state
        budget._shared_budget_exceeded = None
        budget._model_pricing = None

        # Initialize with pricing
        init_shared_budget_state(
            token_limit=1000,
            cost_limit=1.0,
            model_pricing=(5.00, 15.00),
        )

        # Get initializer for Pool
        initializer, args = get_pool_initializer()

        assert initializer is not None
        assert args is not None
        # Args should include: budget_exceeded, token_count, prompt_tokens,
        # completion_tokens, cost_cents, api_calls, token_limit, cost_limit, model_pricing
        assert len(args) == 9
        # Last arg should be the model pricing tuple
        assert args[-1] == (5.00, 15.00)

    def test_sync_from_shared_state(self):
        """Test BudgetManager syncs correctly from shared state."""
        from garak.budget import init_shared_budget_state, update_shared_usage
        from garak import budget

        # Reset
        budget._shared_budget_exceeded = None

        manager = BudgetManager(token_limit=10000)
        manager.init_shared_state(model="gpt-4o")

        # Simulate workers updating shared state
        update_shared_usage(tokens=100, cost_cents=5, prompt_tokens=60, completion_tokens=40)
        update_shared_usage(tokens=200, cost_cents=10, prompt_tokens=120, completion_tokens=80)

        # Sync from shared state
        manager.sync_from_shared_state()

        # Manager should reflect combined usage
        assert manager.total_tokens == 300
        assert manager.total_prompt_tokens == 180
        assert manager.total_completion_tokens == 120
