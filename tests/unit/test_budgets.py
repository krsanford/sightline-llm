"""Cycle 3 W17 (D8/R3/A10): per-tag daily token budgets, WARN mode only (tags are unauthenticated until a later unit,
so a budget never blocks; it records a `budget:<prefix>` reason that foundry perf alerts on)."""
import calendar
import time

import pytest
from fastapi.testclient import TestClient

from sightline import budgets
from sightline.config import Settings
from sightline.engine import Bus
from sightline.policy import Policy
from sightline.server import create_app
from sightline.store import Call, Store

NOW = calendar.timegm((2026, 10, 26, 15, 0, 0))
DAY0 = calendar.timegm((2026, 10, 26, 0, 0, 0))


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    for ts, tag, i, o in [(DAY0 + 10, "foundry/fd-a/01-implementer", 400, 100), (DAY0 + 20, "foundry/fd-b/01-review", 300, 0),
                          (DAY0 - 10, "foundry/fd-old/01-implementer", 9999, 9999), (DAY0 + 30, "other/x", 5000, 0),
                          (DAY0 + 40, "foundryX/y", 7000, 0), (DAY0 + 50, None, 8000, 0)]:
        s.insert(Call(ts=ts, provider="ollama", model="m", tag=tag, input_tokens=i, output_tokens=o, status=200))
    return s


def test_utc_day_start():
    assert budgets.day_start(NOW) == DAY0


def test_tag_tokens_today_by_prefix(store):
    assert store.tag_tokens_since("foundry/", DAY0) == 800          # yesterday, foundryX/ and untagged excluded
    assert store.tag_tokens_since("other/", DAY0) == 5000
    assert store.tag_tokens_since("foundry%", DAY0) == 0             # LIKE wildcards are literal, not patterns


def test_reason_when_over(store):
    assert budgets.budget_reason({"foundry/": 1000}, store, "foundry/fd-c/01-fixer", 150, NOW) is None   # 950
    assert budgets.budget_reason({"foundry/": 1000}, store, "foundry/fd-c/01-fixer", 250, NOW) == "budget:foundry/"


def test_longest_prefix_wins(store):
    b = {"foundry/": 10**9, "foundry/fd-c/": 100}
    assert budgets.budget_reason(b, store, "foundry/fd-c/01-fixer", 150, NOW) == "budget:foundry/fd-c/"
    assert budgets.budget_reason(b, store, "foundry/fd-z/01-fixer", 150, NOW) is None


def test_no_tag_or_no_match(store):
    assert budgets.budget_reason({"foundry/": 1}, store, None, 10**6, NOW) is None
    assert budgets.budget_reason({"foundry/": 1}, store, "elsewhere/q", 10**6, NOW) is None
    assert budgets.budget_reason({}, store, "foundry/x", 10**6, NOW) is None


def test_settings_defaults_and_setup(tmp_path):
    s = Settings(home=tmp_path)
    assert s.budgets == {} and s.budget_mode == "warn"
    s2 = Settings(home=tmp_path, budgets={"foundry/": 5_000_000})
    app = create_app(s2, Store(tmp_path / "t.db"), Policy(), Bus())
    out = TestClient(app, base_url=f"http://127.0.0.1:{s2.ui_port}").get("/api/setup").json()
    assert out["budgets"] == {"foundry/": 5_000_000} and out["budget_mode"] == "warn"


def test_engine_records_reason_without_blocking():
    import inspect

    from sightline import engine
    src = inspect.getsource(engine.SightlineAddon._finish)
    assert "budgets.budget_reason(" in src and "call.reasons" in src
    assert "blocked" not in src.split("budgets.budget_reason(")[1].split("\n")[0]
