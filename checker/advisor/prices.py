"""What the advisor's requests cost, to show before sending (Phase 3 plan,
PR 3.2). US dollars per million tokens, from Anthropic's published prices
as of the date below; a model not listed has no estimate, and the run asks
before sending."""

from dataclasses import dataclass
from typing import Any

PRICES_AS_OF = "2026-10-29"


@dataclass(frozen=True)
class Price:
    input: float
    output: float
    cache_read: float

    @property
    def cache_write(self) -> float:  # five-minute cache writes cost 1.25 times input
        return self.input * 1.25


# Cache reads for Claude Opus 4.8 and Claude Haiku 5.5 are taken as a tenth
# of input, the usual rate; the others are as published.
PRICES = {
    "claude-opus-5-5": Price(4.00, 20.00, 0.20),
    "claude-opus-5": Price(5.00, 25.00, 0.50),
    "claude-opus-4-8": Price(5.00, 25.00, 0.50),
    "claude-sonnet-5-5": Price(2.00, 10.00, 0.20),
    "claude-haiku-5-5": Price(0.10, 0.50, 0.01),
}


def estimate(model: str, input_tokens: int, max_output_tokens: int) -> tuple[float, float] | None:
    """(the input's cost, the most the output can cost) for a request, or
    None for a model without a price."""
    price = PRICES.get(model)
    if price is None:
        return None
    return input_tokens * price.input / 1e6, max_output_tokens * price.output / 1e6


def cost(model: str, usage: dict[str, Any]) -> float | None:
    """What a request cost, from the usage the response reported."""
    price = PRICES.get(model)
    if price is None:
        return None
    return (
        (usage.get("input_tokens") or 0) * price.input
        + (usage.get("cache_creation_input_tokens") or 0) * price.cache_write
        + (usage.get("cache_read_input_tokens") or 0) * price.cache_read
        + (usage.get("output_tokens") or 0) * price.output
    ) / 1e6
