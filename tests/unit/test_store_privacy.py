"""S10: storage minimization — retention purge, metadata-only capture, file permissions, no credentials."""
import json
import stat
import time

from sightline.policy import Policy
from sightline.store import Call, Store

DAY = 86400


def test_db_file_is_owner_only(tmp_path):
    Store(tmp_path / "s.db")
    assert stat.S_IMODE((tmp_path / "s.db").stat().st_mode) == 0o600


def test_retention_purge_clears_old_bodies_then_old_rows(tmp_path):
    s = Store(tmp_path / "s.db")
    now = time.time()
    fresh = s.insert(Call(ts=now - 1 * DAY, prompt="fresh", response="fresh"))
    week_old = s.insert(Call(ts=now - 10 * DAY, prompt="old", response="old"))
    month_old = s.insert(Call(ts=now - 40 * DAY, prompt="ancient", response="ancient"))
    s.purge(body_days=7, metadata_days=30, now=now)
    assert s.get(fresh)["prompt"] == "fresh"
    assert s.get(week_old)["prompt"] is None and s.get(week_old)["response"] is None   # body gone, metadata kept
    assert s.get(month_old) is None                                                    # row gone entirely


def test_metadata_mode_stores_no_text(tmp_path):
    s = Store(tmp_path / "s.db", capture_bodies="metadata")
    cid = s.insert(Call(prompt="secret plans", response="reply", model="m"))
    row = s.get(cid)
    assert row["prompt"] is None and row["response"] is None and row["model"] == "m"
    assert b"secret plans" not in (tmp_path / "s.db").read_bytes()


def test_redacted_prompt_is_what_gets_stored(tmp_path):
    body = json.dumps({"messages": [{"role": "user", "content": "deploy with AKIAIOSFODNN7EXAMPLE"}]}).encode()
    d = Policy().evaluate("openai", "gpt-5.5", "api.openai.com", body)
    s = Store(tmp_path / "s.db")
    cid = s.insert(Call(prompt=json.loads(d.body)["messages"][0]["content"], findings=d.findings, action=d.action))
    assert "AKIAIOSFODNN7EXAMPLE" not in s.get(cid)["prompt"]
    s.db.execute("PRAGMA wal_checkpoint(FULL)")
    assert b"AKIAIOSFODNN7EXAMPLE" not in (tmp_path / "s.db").read_bytes()
