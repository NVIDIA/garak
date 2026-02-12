# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Token usage tracking and cost management for garak scans.

This module provides functionality to track token usage during LLM scans
and enforce budget limits to control costs when using commercial APIs.

Example usage:
    from garak.budget import BudgetManager, TokenUsage

    # Initialize with limits
    manager = BudgetManager(cost_limit=10.00, token_limit=100000)

    # Record usage from API response
    usage = TokenUsage(
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        model="gpt-4o"
    )
    cost = manager.record_usage(usage)

    # Get summary at end of run
    summary = manager.get_summary()
"""

__all__ = [
    "TokenUsage",
    "CostInfo",
    "BudgetManager",
    "BudgetExceededError",
    "is_budget_exceeded",
    "init_shared_budget_state",
    "get_pool_initializer",
    "get_budget_limits",
    "get_model_pricing",
    "mark_budget_exceeded",
    "update_shared_usage",
    "get_shared_usage",
]

import logging
import multiprocessing
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from multiprocessing.sharedctypes import SynchronizedBase
from typing import Callable, Dict, List, Optional, Tuple

import yaml

from garak import _config
from garak.exception import BudgetExceededError


logger = logging.getLogger(__name__)

# Shared state for multiprocessing budget enforcement
# These are module-level to be accessible across process boundaries
_shared_token_count: Optional[SynchronizedBase] = None
_shared_prompt_tokens: Optional[SynchronizedBase] = None
_shared_completion_tokens: Optional[SynchronizedBase] = None
_shared_cost_cents: Optional[SynchronizedBase] = None  # Store as cents (int) to avoid float precision issues
_shared_budget_exceeded: Optional[SynchronizedBase] = None
_shared_api_calls: Optional[SynchronizedBase] = None

# Budget limits - stored here so they can be passed to worker processes
_token_limit: Optional[int] = None
_cost_limit: Optional[float] = None

# Model pricing for worker processes (tuple of input_price, output_price per 1M tokens)
_model_pricing: Optional[Tuple[float, float]] = None


def init_shared_budget_state(
    token_limit: Optional[int],
    cost_limit: Optional[float],
    model_pricing: Optional[Tuple[float, float]] = None,
) -> None:
    """Initialize shared state for multiprocessing budget tracking.

    This must be called before spawning worker processes to enable
    pre-flight budget checking in parallel execution.

    Args:
        token_limit: Maximum tokens allowed (None = unlimited)
        cost_limit: Maximum cost in USD allowed (None = unlimited)
        model_pricing: Tuple of (input_price, output_price) per 1M tokens.
                      If None, defaults will be used from model_pricing.yaml.
    """
    global _shared_token_count, _shared_prompt_tokens, _shared_completion_tokens
    global _shared_cost_cents, _shared_budget_exceeded, _shared_api_calls
    global _token_limit, _cost_limit, _model_pricing

    _shared_token_count = multiprocessing.Value('i', 0)  # 'i' = signed int
    _shared_prompt_tokens = multiprocessing.Value('i', 0)
    _shared_completion_tokens = multiprocessing.Value('i', 0)
    _shared_cost_cents = multiprocessing.Value('i', 0)  # Store cost as cents
    _shared_budget_exceeded = multiprocessing.Value('b', False)  # 'b' = boolean (signed char)
    _shared_api_calls = multiprocessing.Value('i', 0)  # Track API call count

    # Store limits so they can be passed to workers
    _token_limit = token_limit
    _cost_limit = cost_limit
    _model_pricing = model_pricing

    logger.debug(
        "Initialized shared budget state: token_limit=%s, cost_limit=%s, model_pricing=%s",
        token_limit, cost_limit, model_pricing
    )


def _pool_initializer(
    budget_exceeded_flag: SynchronizedBase,
    token_count: Optional[SynchronizedBase],
    prompt_tokens: Optional[SynchronizedBase],
    completion_tokens: Optional[SynchronizedBase],
    cost_cents: Optional[SynchronizedBase],
    api_calls: Optional[SynchronizedBase],
    token_limit: Optional[int],
    cost_limit: Optional[float],
    model_pricing: Optional[Tuple[float, float]],
) -> None:
    """Initializer function for multiprocessing Pool workers.

    This function is called once when each worker process starts.
    It sets the module-level shared state so workers can check and update budget.

    Args:
        budget_exceeded_flag: The shared Value object for budget exceeded flag
        token_count: The shared Value object for total token count
        prompt_tokens: The shared Value object for prompt token count
        completion_tokens: The shared Value object for completion token count
        cost_cents: The shared Value object for cost in cents
        api_calls: The shared Value object for API call count
        token_limit: Maximum tokens allowed (None = unlimited)
        cost_limit: Maximum cost in USD allowed (None = unlimited)
        model_pricing: Tuple of (input_price, output_price) per 1M tokens
    """
    global _shared_budget_exceeded, _shared_token_count, _shared_prompt_tokens, _shared_completion_tokens
    global _shared_cost_cents, _shared_api_calls
    global _token_limit, _cost_limit, _model_pricing
    _shared_budget_exceeded = budget_exceeded_flag
    _shared_token_count = token_count
    _shared_prompt_tokens = prompt_tokens
    _shared_completion_tokens = completion_tokens
    _shared_cost_cents = cost_cents
    _shared_api_calls = api_calls
    _token_limit = token_limit
    _cost_limit = cost_limit
    _model_pricing = model_pricing


def get_pool_initializer() -> Tuple[Optional[Callable], Optional[Tuple]]:
    """Get the initializer function and args for Pool creation.

    Returns:
        Tuple of (initializer_function, initializer_args) to pass to Pool()
    """
    global _shared_budget_exceeded, _shared_token_count, _shared_prompt_tokens, _shared_completion_tokens
    global _shared_cost_cents, _shared_api_calls
    global _token_limit, _cost_limit, _model_pricing
    if _shared_budget_exceeded is None:
        return (None, None)
    return (
        _pool_initializer,
        (_shared_budget_exceeded, _shared_token_count, _shared_prompt_tokens, _shared_completion_tokens,
         _shared_cost_cents, _shared_api_calls, _token_limit, _cost_limit, _model_pricing),
    )


def is_budget_exceeded() -> bool:
    """Check if budget has been exceeded (for use in worker processes).

    Returns:
        True if budget was exceeded, False otherwise or if not initialized
    """
    global _shared_budget_exceeded
    if _shared_budget_exceeded is None:
        return False
    return bool(_shared_budget_exceeded.value)


def get_budget_limits() -> Tuple[Optional[int], Optional[float]]:
    """Get the configured budget limits.

    Returns:
        Tuple of (token_limit, cost_limit)
    """
    global _token_limit, _cost_limit
    return _token_limit, _cost_limit


def get_model_pricing() -> Tuple[float, float]:
    """Get model pricing for cost calculation in worker processes.

    Returns:
        Tuple of (input_price, output_price) per 1M tokens.
        Falls back to conservative defaults if not set.
    """
    global _model_pricing
    if _model_pricing is not None:
        return _model_pricing
    # Default conservative pricing (per 1M tokens)
    # Uses high estimates to avoid underestimating costs
    return (5.00, 15.00)


def mark_budget_exceeded() -> None:
    """Mark budget as exceeded (thread-safe)."""
    global _shared_budget_exceeded
    if _shared_budget_exceeded is not None:
        _shared_budget_exceeded.value = True


def update_shared_usage(
    tokens: int, cost_cents: int, prompt_tokens: int = 0, completion_tokens: int = 0
) -> None:
    """Update shared usage counters (thread-safe).

    Args:
        tokens: Number of total tokens to add
        cost_cents: Cost in cents (integer) to add
        prompt_tokens: Number of prompt tokens to add
        completion_tokens: Number of completion tokens to add
    """
    global _shared_token_count, _shared_prompt_tokens, _shared_completion_tokens
    global _shared_cost_cents, _shared_api_calls
    if _shared_token_count is not None:
        with _shared_token_count.get_lock():
            _shared_token_count.value += tokens
    if _shared_prompt_tokens is not None:
        with _shared_prompt_tokens.get_lock():
            _shared_prompt_tokens.value += prompt_tokens
    if _shared_completion_tokens is not None:
        with _shared_completion_tokens.get_lock():
            _shared_completion_tokens.value += completion_tokens
    if _shared_cost_cents is not None:
        with _shared_cost_cents.get_lock():
            _shared_cost_cents.value += cost_cents
    if _shared_api_calls is not None:
        with _shared_api_calls.get_lock():
            _shared_api_calls.value += 1


def get_shared_usage() -> Tuple[int, float, int, int, int]:
    """Get current shared usage values.

    Returns:
        Tuple of (total_tokens, total_cost_usd, api_calls, prompt_tokens, completion_tokens)
    """
    global _shared_token_count, _shared_prompt_tokens, _shared_completion_tokens
    global _shared_cost_cents, _shared_api_calls
    tokens = _shared_token_count.value if _shared_token_count else 0
    prompt = _shared_prompt_tokens.value if _shared_prompt_tokens else 0
    completion = _shared_completion_tokens.value if _shared_completion_tokens else 0
    cost_cents = _shared_cost_cents.value if _shared_cost_cents else 0
    api_calls = _shared_api_calls.value if _shared_api_calls else 0
    return tokens, cost_cents / 100.0, api_calls, prompt, completion


@dataclass
class TokenUsage:
    """Represents token usage from a single API call.

    Attributes:
        prompt_tokens: Number of tokens in the input/prompt
        completion_tokens: Number of tokens in the output/completion
        total_tokens: Total tokens (prompt + completion)
        model: Model name/identifier
        estimated: True if counts were estimated from characters
        timestamp: ISO format timestamp of when usage was recorded
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = ""
    estimated: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        # Calculate total if not provided
        if self.total_tokens == 0 and (self.prompt_tokens or self.completion_tokens):
            self.total_tokens = self.prompt_tokens + self.completion_tokens


@dataclass
class CostInfo:
    """Cost calculation result for token usage.

    Attributes:
        input_cost: Cost for input/prompt tokens in USD
        output_cost: Cost for output/completion tokens in USD
        total_cost: Total cost in USD
        currency: Currency code (default: USD)
    """

    input_cost: float = 0.0
    output_cost: float = 0.0
    total_cost: float = 0.0
    currency: str = "USD"

    def __post_init__(self):
        # Calculate total if not provided
        if self.total_cost == 0.0 and (self.input_cost or self.output_cost):
            self.total_cost = self.input_cost + self.output_cost


class BudgetManager:
    """Centralized budget tracking and enforcement for garak scans.

    This class tracks token usage across all API calls during a scan,
    calculates costs based on model pricing, and enforces budget limits.

    Attributes:
        cost_limit: Maximum allowed cost in USD (None = unlimited)
        token_limit: Maximum allowed tokens (None = unlimited)
        total_prompt_tokens: Running total of prompt tokens
        total_completion_tokens: Running total of completion tokens
        total_tokens: Running total of all tokens
        total_cost: Running total cost in USD
        usage_log: List of all TokenUsage records
    """

    def __init__(
        self,
        cost_limit: Optional[float] = None,
        token_limit: Optional[int] = None,
    ):
        """Initialize the budget manager.

        Args:
            cost_limit: Maximum cost in USD before stopping (None = no limit)
            token_limit: Maximum tokens before stopping (None = no limit)

        Raises:
            ValueError: If cost_limit or token_limit is not positive
        """
        if cost_limit is not None and cost_limit <= 0:
            raise ValueError("cost_limit must be positive")
        if token_limit is not None and token_limit <= 0:
            raise ValueError("token_limit must be positive")

        self.cost_limit = cost_limit
        self.token_limit = token_limit
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.total_cost = 0.0
        self.usage_log: List[TokenUsage] = []
        self._pricing: Dict = {}
        self._estimation_config: Dict = {}
        self._load_pricing()

    def _load_pricing(self) -> None:
        """Load model pricing from YAML configuration file."""
        pricing_path = (
            Path(_config.transient.package_dir) / "resources" / "model_pricing.yaml"
        )

        if not pricing_path.exists():
            logger.warning(
                "Model pricing file not found at %s, using defaults", pricing_path
            )
            self._pricing = {}
            self._estimation_config = {
                "default_chars_per_token": 4,
                "default_input_price": 5.00,
                "default_output_price": 15.00,
            }
            return

        with open(pricing_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self._pricing = data.get("pricing", {})
        self._estimation_config = data.get(
            "estimation",
            {
                "default_chars_per_token": 4,
                "default_input_price": 5.00,
                "default_output_price": 15.00,
            },
        )

    def _get_model_pricing(self, model: str) -> Tuple[float, float]:
        """Get pricing for a specific model.

        Args:
            model: Model name/identifier

        Returns:
            Tuple of (input_price_per_1m, output_price_per_1m)
        """
        # Try exact match first across all providers
        for provider, models in self._pricing.items():
            if model in models:
                pricing = models[model]
                return pricing.get("input", 0), pricing.get("output", 0)

        # Try partial match (model name might be prefixed or have version suffix)
        model_lower = model.lower()
        for provider, models in self._pricing.items():
            for model_name, pricing in models.items():
                if model_name.lower() in model_lower or model_lower in model_name.lower():
                    return pricing.get("input", 0), pricing.get("output", 0)

        # Return defaults if not found
        logger.debug("No pricing found for model '%s', using defaults", model)
        return (
            self._estimation_config.get("default_input_price", 5.00),
            self._estimation_config.get("default_output_price", 15.00),
        )

    def calculate_cost(self, usage: TokenUsage) -> CostInfo:
        """Calculate the cost for a given token usage.

        Args:
            usage: TokenUsage object with token counts and model info

        Returns:
            CostInfo with calculated costs
        """
        input_price, output_price = self._get_model_pricing(usage.model)

        # Prices are per 1M tokens
        input_cost = (usage.prompt_tokens / 1_000_000) * input_price
        output_cost = (usage.completion_tokens / 1_000_000) * output_price

        return CostInfo(
            input_cost=input_cost,
            output_cost=output_cost,
            total_cost=input_cost + output_cost,
        )

    def record_usage(self, usage: TokenUsage) -> CostInfo:
        """Record token usage and update running totals.

        This method records the usage, calculates cost, updates totals,
        and checks budget limits.

        Args:
            usage: TokenUsage object from an API call

        Returns:
            CostInfo with the cost for this usage

        Raises:
            BudgetExceededError: If cost_limit or token_limit is exceeded
        """
        # Add to log
        self.usage_log.append(usage)

        # Update totals
        self.total_prompt_tokens += usage.prompt_tokens
        self.total_completion_tokens += usage.completion_tokens
        self.total_tokens += usage.total_tokens

        # Calculate and add cost
        cost = self.calculate_cost(usage)
        self.total_cost += cost.total_cost

        # Log the usage
        logger.debug(
            "Token usage recorded: %d prompt, %d completion, $%.6f (model: %s)",
            usage.prompt_tokens,
            usage.completion_tokens,
            cost.total_cost,
            usage.model,
        )

        # Check limits
        self.check_budget()

        return cost

    def check_budget(self) -> bool:
        """Check if current usage is within budget limits.

        Returns:
            True if within limits

        Raises:
            BudgetExceededError: If any limit is exceeded
        """
        if self.token_limit is not None and self.total_tokens > self.token_limit:
            mark_budget_exceeded()
            raise BudgetExceededError(
                f"Token limit exceeded: {self.total_tokens:,} tokens used, "
                f"limit is {self.token_limit:,} tokens"
            )

        if self.cost_limit is not None and self.total_cost > self.cost_limit:
            mark_budget_exceeded()
            raise BudgetExceededError(
                f"Cost limit exceeded: ${self.total_cost:.4f} spent, "
                f"limit is ${self.cost_limit:.2f}"
            )

        return True

    def can_proceed(self) -> bool:
        """Check if we can proceed with another API call (pre-flight check).

        This method checks the shared state to see if budget has been exceeded
        by any worker process. Use this before dispatching new work in parallel
        execution to prevent unnecessary API calls.

        Returns:
            True if we can proceed, False if budget has been exceeded
        """
        # Check shared state first (for multiprocessing scenarios)
        if is_budget_exceeded():
            return False

        # Also check local state
        if self.token_limit is not None and self.total_tokens >= self.token_limit:
            return False

        if self.cost_limit is not None and self.total_cost >= self.cost_limit:
            return False

        return True

    def init_shared_state(self, model: Optional[str] = None) -> None:
        """Initialize shared state for multiprocessing budget tracking.

        Call this before spawning worker processes to enable pre-flight
        budget checking in parallel execution.

        Args:
            model: Model name to look up pricing for. If provided, the model's
                   pricing will be passed to worker processes for accurate cost
                   calculation.
        """
        model_pricing = None
        if model:
            model_pricing = self._get_model_pricing(model)
        init_shared_budget_state(self.token_limit, self.cost_limit, model_pricing)

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count from text using character ratio.

        This is a fallback when actual token counts are not available.

        Args:
            text: Input text to estimate tokens for

        Returns:
            Estimated token count
        """
        chars_per_token = self._estimation_config.get("default_chars_per_token", 4)
        return max(1, len(text) // chars_per_token)

    def estimate_usage(
        self, prompt_text: str, completion_text: str, model: str
    ) -> TokenUsage:
        """Create an estimated TokenUsage from text content.

        Used when the API doesn't return actual token counts.

        Args:
            prompt_text: The prompt/input text
            completion_text: The completion/output text
            model: Model name

        Returns:
            TokenUsage with estimated=True
        """
        prompt_tokens = self.estimate_tokens(prompt_text)
        completion_tokens = self.estimate_tokens(completion_text)

        return TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            model=model,
            estimated=True,
        )

    def sync_from_shared_state(self) -> None:
        """Sync totals from shared multiprocessing state.

        In parallel execution, workers update shared counters directly.
        This method syncs those values back to the BudgetManager instance
        so get_summary() reflects the actual usage.
        """
        shared_tokens, _, shared_api_calls, shared_prompt, shared_completion = get_shared_usage()
        if shared_tokens > self.total_tokens:
            self.total_tokens = shared_tokens
            self.total_prompt_tokens = shared_prompt
            self.total_completion_tokens = shared_completion

            # Calculate cost using real pricing from model_pricing.yaml
            model_name = None
            try:
                from garak import _config
                model_name = getattr(getattr(_config, "plugins", None), "target_name", None)
            except Exception:
                pass

            if model_name:
                input_price, output_price = self._get_model_pricing(model_name)
            else:
                input_price = self._estimation_config.get("default_input_price", 5.00)
                output_price = self._estimation_config.get("default_output_price", 15.00)

            # Calculate actual cost using prompt and completion breakdown
            self.total_cost = (
                (shared_prompt / 1_000_000) * input_price +
                (shared_completion / 1_000_000) * output_price
            )
        self._shared_api_calls = shared_api_calls

    def get_summary(self) -> Dict:
        """Get a summary of all token usage and costs.

        Returns:
            Dictionary with usage summary suitable for reporting
        """
        # Sync from shared state to get totals from worker processes
        self.sync_from_shared_state()

        # Count estimated vs actual
        estimated_count = sum(1 for u in self.usage_log if u.estimated)
        actual_count = len(self.usage_log) - estimated_count

        # Use shared API call count if available (from parallel workers),
        # otherwise use usage_log length
        api_calls = getattr(self, '_shared_api_calls', 0)
        if api_calls == 0:
            api_calls = len(self.usage_log)

        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "total_cost": round(self.total_cost, 6),
            "currency": "USD",
            "cost_limit": self.cost_limit,
            "token_limit": self.token_limit,
            "api_calls": api_calls,
            "actual_token_counts": actual_count,
            "estimated_token_counts": estimated_count,
            "models_used": list(set(u.model for u in self.usage_log if u.model)),
        }

    def format_summary(self) -> str:
        """Format the usage summary for console output.

        Returns:
            Formatted string for display
        """
        summary = self.get_summary()
        lines = [
            "Token Usage Summary:",
            f"  Total tokens: {summary['total_tokens']:,} "
            f"(prompt: {summary['total_prompt_tokens']:,}, "
            f"completion: {summary['total_completion_tokens']:,})",
            f"  Estimated cost: ${summary['total_cost']:.4f} {summary['currency']}",
            f"  API calls: {summary['api_calls']}",
        ]

        if summary["estimated_token_counts"] > 0:
            lines.append(
                f"  Note: {summary['estimated_token_counts']} calls used estimated token counts"
            )

        if summary["models_used"]:
            lines.append(f"  Models: {', '.join(summary['models_used'])}")

        if summary["cost_limit"]:
            lines.append(f"  Cost limit: ${summary['cost_limit']:.2f}")

        if summary["token_limit"]:
            lines.append(f"  Token limit: {summary['token_limit']:,}")

        return "\n".join(lines)
