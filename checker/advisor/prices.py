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


# The models Anthropic's server-side fallback may re-run a declined request
# on (decision 3): an estimate with the fallback on allows for the dearest.
FALLBACK_MODELS = ("claude-opus-5", "claude-opus-4-8")
# A real case file of 86 000 characters was 35 800 tokens (2026-10-29):
# about 2.4 characters a token, so 2 errs high, as an estimate should.
CHARACTERS_PER_TOKEN = 2


def tokens_in(text: str) -> int:
    """About how many tokens a request is, counted here: nothing is sent to
    estimate it."""
    return len(text) // CHARACTERS_PER_TOKEN + 1


def estimate(
    model: str, input_tokens: int, max_output_tokens: int, fallback: bool = False
) -> tuple[float, float] | None:
    """(the input's cost, the most the output can cost) for a request, or
    None for a model without a price. The input is priced as a cache
    write (a first request writes the cache). With the fallback on, a
    declined request may be billed again on the dearest fallback model."""
    price = PRICES.get(model)
    if price is None:
        return None
    first = (input_tokens * price.cache_write / 1e6, max_output_tokens * price.output / 1e6)
    if not fallback:
        return first
    dearest = max((PRICES[m] for m in FALLBACK_MODELS), key=lambda p: p.input + p.output)
    return (
        first[0] + input_tokens * dearest.cache_write / 1e6,
        first[1] + max_output_tokens * dearest.output / 1e6,
    )


def _priced(price: Price, usage: dict[str, Any]) -> float:
    return (
        (usage.get("input_tokens") or 0) * price.input
        + (usage.get("cache_creation_input_tokens") or 0) * price.cache_write
        + (usage.get("cache_read_input_tokens") or 0) * price.cache_read
        + (usage.get("output_tokens") or 0) * price.output
    ) / 1e6


def cost(model: str, usage: dict[str, Any], iterations: list[dict[str, Any]] = ()) -> float | None:
    """What a request cost: each model that ran priced at its own rate
    (the usage per model), else the whole usage at `model`'s; None when a
    model that ran has no price."""
    if iterations:
        total = 0.0
        for hop in iterations:
            price = PRICES.get(hop.get("model") or model)
            if price is None:
                return None
            total += _priced(price, hop)
        return total
    price = PRICES.get(model)
    return _priced(price, usage) if price is not None else None
