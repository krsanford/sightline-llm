"""Price-table loader and cost calculator for Sightline.

Loads :data:`pricing.yaml` into a :class:`PriceTable` and turns provider
:class:`~sightline.providers.base.Usage` counts into a :class:`Cost`.

The table is an ordered list of price rows, **first match wins**.  Each row
matches on a ``fnmatch`` glob evaluated against the lower-cased model id with any
leading ``provider/`` registry segment stripped, so ``anthropic/claude-sonnet-5-5``
and ``claude-sonnet-5-5`` behave identically.  Cache-read / cache-write tokens are
*subsets* of the input tokens (see :class:`~sightline.providers.base.Usage`); when a
row omits a cache rate the input rate is used as the fallback.

Local "shadow" providers (e.g. Ollama) are free -- ``usd == 0.0`` -- but report a
``shadow_usd`` equal to what the same tokens would have cost on the hosted model
named in their ``as`` entry.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .providers.base import Usage

_PER_MILLION = 1_000_000.0


@dataclass
class Price:
    """Per-1M-token rates for one model family (cache rates may be unset)."""

    provider: str
    match: str
    input: float
    output: float
    cache_read: float | None = None
    cache_write: float | None = None


@dataclass
class Cost:
    """Result of pricing one :class:`Usage`.

    ``usd`` is ``None`` when nothing matched; ``shadow_usd`` is only populated for
    shadow providers and holds the hypothetical hosted price.
    """

    usd: float | None = None
    shadow_usd: float | None = None
    matched: str | None = None


def _normalize_model(model: str | None) -> str | None:
    """Lower-case *model* and strip a leading ``provider/`` registry segment."""
    if model is None:
        return None
    name = model.strip().lower()
    if "/" in name:
        name = name.split("/", 1)[1]
    return name


def _coerce_rate(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


class PriceTable:
    """A loaded price table: ordered rows plus optional shadow providers."""

    def __init__(self, as_of: str | None, prices: list[Price], shadow: dict[str, dict]) -> None:
        self.as_of = as_of
        self._prices = prices
        self._shadow = shadow

    def lookup(self, provider: str, model: str | None) -> Price | None:
        """Return the first price row matching *provider*/*model*, else ``None``."""
        name = _normalize_model(model)
        if name is None:
            return None
        for price in self._prices:
            if price.provider != provider:
                continue
            if fnmatch.fnmatchcase(name, price.match):
                return price
        return None

    def cost(self, provider: str, model: str | None, usage: Usage) -> Cost:
        """Price *usage* for *provider*/*model*."""
        shadow = self._shadow.get(provider)
        if shadow is not None:
            sub = self.lookup(shadow.get("provider"), shadow.get("as"))
            shadow_usd = _price(sub, usage) if sub is not None else None
            return Cost(usd=0.0, shadow_usd=shadow_usd, matched=None)

        price = self.lookup(provider, model)
        if price is None:
            return Cost()
        return Cost(usd=_price(price, usage), shadow_usd=None, matched=price.match)


def _price(price: Price, usage: Usage) -> float:
    """Cost in USD of *usage* at *price*.

    Uncached input is billed at the input rate; cached tokens at their own rate,
    falling back to the input rate when a cache rate is unset.
    """
    uncached = usage.input_tokens - usage.cache_read_tokens - usage.cache_write_tokens
    read_rate = price.cache_read if price.cache_read is not None else price.input
    write_rate = price.cache_write if price.cache_write is not None else price.input
    total = (
        uncached * price.input
        + usage.cache_read_tokens * read_rate
        + usage.cache_write_tokens * write_rate
        + usage.output_tokens * price.output
    )
    return total / _PER_MILLION


def load_table(path: str | Path | None = None) -> PriceTable:
    """Load a :class:`PriceTable` from *path*.

    Defaults to ``pricing.yaml`` next to this module.
    """
    if path is None:
        path = Path(__file__).with_name("pricing.yaml")

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}

    prices: list[Price] = []
    for row in data.get("models") or []:
        prices.append(
            Price(
                provider=str(row["provider"]),
                match=str(row["match"]),
                input=float(row["input"]),
                output=float(row["output"]),
                cache_read=_coerce_rate(row.get("cache_read")),
                cache_write=_coerce_rate(row.get("cache_write")),
            )
        )

    shadow: dict[str, dict] = {}
    for prov, cfg in (data.get("shadow") or {}).items():
        cfg = cfg or {}
        shadow[prov] = {"provider": cfg.get("provider"), "as": cfg.get("as")}

    return PriceTable(as_of=data.get("as_of"), prices=prices, shadow=shadow)
