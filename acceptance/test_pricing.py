import math

from sightline.pricing import PriceTable, load_table
from sightline.providers.base import Usage


def u(i, o, cr=0, cw=0):
    return Usage(input_tokens=i, output_tokens=o, cache_read_tokens=cr, cache_write_tokens=cw, source="reported")


def test_loads_default_table():
    t = load_table()
    assert isinstance(t, PriceTable) and t.as_of == "2026-10-26"


def test_lookup_first_match_and_normalization():
    t = load_table()
    assert t.lookup("openai", "gpt-5.5-mini").input == 0.50
    assert t.lookup("openai", "gpt-5.5-2026-08-01").input == 5.0
    assert t.lookup("openai", "GPT-5.5").input == 5.0
    assert t.lookup("anthropic", "anthropic/claude-opus-5-5").output == 20.0
    assert t.lookup("anthropic", "claude-opus-4-6").input == 5.0
    assert t.lookup("openai", "no-such-model") is None


def test_cost_simple():
    c = load_table().cost("openai", "gpt-5.5", u(1_000_000, 100_000))
    assert math.isclose(c.usd, 5.0 + 3.0) and c.matched == "gpt-5.5*" and c.shadow_usd is None


def test_cost_cache_read_and_write_are_subsets_of_input():
    # 1496 input total = 472 uncached + 1024 cache read; claude-sonnet-5-5: in 2, out 10, cr 0.10
    c = load_table().cost("anthropic", "claude-sonnet-5-5", u(1496, 89, cr=1024))
    expected = (472 * 2.0 + 1024 * 0.10 + 89 * 10.0) / 1e6
    assert math.isclose(c.usd, expected, rel_tol=1e-9)
    # cache write billed at cache_write rate
    c2 = load_table().cost("anthropic", "claude-opus-5-5", u(212, 9, cw=200))
    assert math.isclose(c2.usd, (12 * 4.0 + 200 * 5.0 + 9 * 20.0) / 1e6, rel_tol=1e-9)


def test_cache_rate_falls_back_to_input_rate():
    c = load_table().cost("openai", "gpt-5.6-sol", u(1000, 0, cr=400))
    assert math.isclose(c.usd, 1000 * 4.0 / 1e6)


def test_unknown_model_cost_is_none():
    c = load_table().cost("openai", "mystery", u(10, 10))
    assert c.usd is None and c.matched is None


def test_local_shadow_cost():
    c = load_table().cost("ollama", "qwen3.8:27b-mlx-256k", u(1_000_000, 1_000_000))
    assert c.usd == 0.0 and math.isclose(c.shadow_usd, 2.0 + 10.0)


def test_custom_table(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text('as_of: "x"\nmodels:\n  - {provider: openai, match: "m*", input: 1, output: 2}\n')
    t = load_table(p)
    assert math.isclose(t.cost("openai", "m1", u(1e6, 1e6)).usd, 3.0)
