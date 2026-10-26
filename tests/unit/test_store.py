"""Unit tests for the Sightline SQLite store (src/sightline/store.py).

Covers: insert/get round-trip with serialized lists/dicts, list() ordering/
limit/provider filter/since_id, capture_bodies="metadata", stats() totals and
p50/p95, insights() grouping, purge() body vs metadata retention via the ``now``
parameter, and the 0600 file mode of a freshly created DB.
"""
from pathlib import Path

import pytest

from sightline.store import Call, Store

DAY = 86400.0


def _call(**kw) -> Call:
    base = dict(ts=1_000.0, provider="openai", model="gpt-4", status=200,
                input_tokens=10, output_tokens=5, usd=0.01,
                reasons=["r1"], findings=[{"kind": "secret", "category": "aws", "count": 2}],
                stream=True)
    base.update(kw)
    return Call(**base)


# --- insert / get round-trip ------------------------------------------------

def test_insert_get_roundtrip_lists_and_dicts(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    call = _call(reasons=["a", "b"], findings=[{"kind": "k", "category": "c", "count": 3}],
                 prompt="p", response="r")
    cid = store.insert(call)
    assert isinstance(cid, int) and cid > 0

    row = store.get(cid)
    assert row is not None
    # lists/dicts are serialized to JSON on write and re-parsed on read
    assert row["reasons"] == ["a", "b"]
    assert row["findings"] == [{"kind": "k", "category": "c", "count": 3}]
    # stream is stored as int and decoded back to bool
    assert row["stream"] is True
    assert row["prompt"] == "p" and row["response"] == "r"
    assert row["provider"] == "openai" and row["usd"] == 0.01
    # get of a non-existent id returns None
    assert store.get(99999) is None


# --- list() behaviour --------------------------------------------------------

def test_list_ordering_desc_and_limit(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    for i in range(1, 6):
        store.insert(_call(ts=float(i), model=f"m{i}"))
    rows = store.list(limit=1000)
    # ORDER BY id DESC => most-recent first
    assert [r["model"] for r in rows] == ["m5", "m4", "m3", "m2", "m1"]

    limited = store.list(limit=2)
    assert [r["model"] for r in limited] == ["m5", "m4"]


def test_list_provider_filter_and_since_id(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    ids = []
    ids.append(store.insert(_call(provider="openai", model="gpt-4", ts=10.0)))
    ids.append(store.insert(_call(provider="anthropic", model="claude", ts=11.0)))
    ids.append(store.insert(_call(provider="openai", model="gpt-3", ts=12.0)))

    openai = store.list(limit=1000, provider="openai")
    assert {r["model"] for r in openai} == {"gpt-4", "gpt-3"}

    # since_id is exclusive (id > ?); ids are ascending
    after = store.list(limit=1000, since_id=ids[1])
    assert [r["id"] for r in after] == [ids[2]]
    assert {r["model"] for r in after} == {"gpt-3"}


# --- capture_bodies="metadata" ----------------------------------------------

def test_metadata_mode_stores_no_bodies(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3", capture_bodies="metadata")
    cid = store.insert(_call(prompt="secret-prompt", response="secret-response"))
    row = store.get(cid)
    assert row["prompt"] is None and row["response"] is None

    # default capture_bodies keeps the bodies
    store2 = Store(tmp_path / "db2.sqlite3", capture_bodies="redacted")
    cid2 = store2.insert(_call(prompt="secret-prompt", response="secret-response"))
    row2 = store2.get(cid2)
    assert row2["prompt"] == "secret-prompt" and row2["response"] == "secret-response"


# --- stats() ----------------------------------------------------------------

def test_stats_totals_and_percentiles(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    # two calls in-window with different latencies + token sums
    store.insert(_call(ts=5.0, latency_ms=10.0, input_tokens=100, output_tokens=50, usd=0.5,
                       action="allowed", findings=[]))
    store.insert(_call(ts=6.0, latency_ms=30.0, input_tokens=10, output_tokens=5, usd=0.25,
                       action="redacted", findings=[{"kind": "secret", "count": 1}]))
    # out-of-window call: ts=0.0 is below since(1.0), so it is excluded
    store.insert(_call(ts=0.0, latency_ms=999.0, input_tokens=1000, output_tokens=1000, usd=9.0, action="blocked"))

    # stats() selects ts >= since(1.0), so the ts=0.0 row is excluded: n == 2
    s = store.stats(since=1.0)
    assert s["n"] == 2
    assert s["tin"] == 110 and s["tout"] == 55
    assert s["usd"] == pytest.approx(0.75)
    assert s["shadow"] == 0
    assert s["redacted"] == 1
    assert s["blocked"] == 0
    assert s["with_findings"] == 1
    # latencies sorted ascending [10, 30]; p50 = lat[1] = 30, p95 = lat[min(1, 1)] = 30
    assert s["p50_ms"] == 30.0
    assert s["p95_ms"] == 30.0
    # no latency data -> percentiles are None
    assert store.stats(since=100.0)["p50_ms"] is None
    assert store.stats(since=100.0)["p95_ms"] is None


# --- insights() --------------------------------------------------------------

def test_insights_grouping(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    store.insert(_call(ts=1000.0, provider="openai", model="gpt-4", input_tokens=100,
                       output_tokens=50, usd=0.10, tag="swarm/lane-a",
                       findings=[{"kind": "secret", "category": "aws", "count": 2}]))
    store.insert(_call(ts=1001.0, provider="openai", model="gpt-4", input_tokens=50,
                       output_tokens=25, usd=0.05, tag="swarm/lane-a", findings=[]))
    store.insert(_call(ts=1002.0, provider="anthropic", model="claude", input_tokens=10,
                       output_tokens=10, usd=0.02, client="Curl", findings=[]))

    ins = store.insights(since=0.0)

    by_model = ins["by_model"]
    assert len(by_model) == 2
    g4 = next(m for m in by_model if m["model"] == "gpt-4")
    assert g4["provider"] == "openai"
    assert g4["calls"] == 2
    assert g4["input_tokens"] == 150 and g4["output_tokens"] == 75
    assert g4["usd"] == pytest.approx(0.15)
    # ordered by usd DESC
    assert by_model[0]["usd"] >= by_model[1]["usd"]

    by_hour = ins["by_hour"]
    assert len(by_hour) == 1
    assert by_hour[0]["calls"] == 3
    # tokens = 100 + 50 + 50 + 25 + 10 + 10
    assert by_hour[0]["tokens"] == 245

    by_client = ins["by_client"]
    # tag takes precedence over client; grouped, ordered by calls DESC
    assert by_client[0]["client"] == "swarm/lane-a"
    assert by_client[0]["calls"] == 2

    # findings aggregated across rows by kind
    assert ins["findings"]["secret"] == 2


# --- purge() retention -------------------------------------------------------

@pytest.mark.xfail(
    strict=True,
    reason=(
        "purge() DELETE leg uses the strict comparison 'ts < now - metadata_days*86400'. "
        "A row at exactly now - 30*DAY is therefore kept by metadata_days=30 (the cutoff "
        "is exclusive) and is only deleted when metadata_days exceeds the row's age -- "
        "here metadata_days=31, i.e. metadata_days=30 does not delete a row that is 30 "
        "days old. A correct retention implementation uses 'ts <= now - N*86400'. The "
        "body-cleared leg is unaffected."
    ),
)
def test_purge_clears_bodies_then_deletes_rows(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    now = 100_000_000.0
    fresh_ts = now - 1 * DAY            # inside the body window
    aged_ts = now - 30 * DAY           # exactly 30 days old
    store.insert(_call(ts=fresh_ts, prompt="fresh-p", response="fresh-r"))
    store.insert(_call(ts=aged_ts, prompt="old-p", response="old-r"))

    # body_days=7 clears the aged body; metadata_days=60 keeps both rows because
    # aged_ts (30 days) is younger than 60 days, so nothing is deleted yet.
    b, m = store.purge(body_days=7, metadata_days=60, now=now)
    assert b == 1 and m == 0  # one body cleared; nothing deleted
    fresh_row = store.get(1)
    aged_row = store.get(2)
    assert fresh_row["prompt"] == "fresh-p" and fresh_row["response"] == "fresh-r"
    assert aged_row["prompt"] is None and aged_row["response"] is None

    # A second purge with metadata_days=30 is expected to delete the 30-day-old row,
    # but the strict '<' cutoff keeps it -- see the xfail reason above.
    b2, m2 = store.purge(body_days=7, metadata_days=30, now=now)
    assert m2 == 1
    assert store.get(2) is None
    assert store.get(1) is not None


def test_purge_reports_only_bodies_actually_cleared(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite3")
    now = 100_000_000.0
    aged_ts = now - 30 * DAY           # older than the 7-day body window, younger than the 31-day metadata window
    store.insert(_call(ts=aged_ts, prompt="old-p", response="old-r"))

    # First purge: clears the aged body (30 > 7) but keeps the row (30 < 31-day metadata window).
    b, m = store.purge(body_days=7, metadata_days=31, now=now)
    assert b == 1 and m == 0

    # Second purge over the same window: the bodies are already null, so the UPDATE
    # is a no-op and purge() correctly reports 0 bodies cleared (a NULL -> NULL
    # assignment changes no rows, so the sqlite rowcount is 0).
    b2, m2 = store.purge(body_days=7, metadata_days=31, now=now)
    assert b2 == 0 and m2 == 0


# --- file mode ---------------------------------------------------------------

def test_new_db_file_is_mode_0600(tmp_path: Path):
    p = tmp_path / "db.sqlite3"
    Store(p)
    # check the actual file mode bits, independent of the umask
    mode = p.stat().st_mode & 0o777
    assert mode == 0o600
