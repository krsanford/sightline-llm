"""Cycle 3 W12a (D7 audit v2): Sightline records the NAMES of the tools offered in each request (never their
schemas or descriptions), so foundry can audit per role which tools an agent actually got, from the wire."""
import inspect
import json
import sqlite3

from sightline import engine
from sightline.providers import ollama, openai
from sightline.providers.base import tool_names_from
from sightline.store import Call, Store

OPENAI_TOOLS = [{"type": "function", "function": {"name": "read_file", "description": "SECRET-DESC", "parameters": {}}},
                {"type": "function", "function": {"name": "terminal"}}]


def test_tool_names_from_shapes():
    assert tool_names_from(OPENAI_TOOLS) == ["read_file", "terminal"]
    assert tool_names_from([{"name": "web_search", "input_schema": {}}]) == ["web_search"]     # flat shape
    assert tool_names_from(None) == [] and tool_names_from("x") == [] and tool_names_from([1, None, {}]) == []


def test_tool_names_validated_deduped_capped():
    weird = [{"name": "ok_1"}, {"name": "ok_1"}, {"name": "bad name with spaces"}, {"name": "x" * 65},
             {"name": "<script>"}, {"name": "mcp.server:tool-2"}]
    assert tool_names_from(weird) == ["ok_1", "mcp.server:tool-2"]
    many = [{"name": f"t{i}"} for i in range(100)]
    assert len(tool_names_from(many)) == 64


def test_parsers_fill_tool_names():
    body = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}], "tools": OPENAI_TOOLS}).encode()
    for mod, path in ((openai, "/v1/chat/completions"), (ollama, "/v1/chat/completions"), (ollama, "/api/chat")):
        r = mod.parse_request(path, body)
        assert r.tool_names == ["read_file", "terminal"] and r.tool_count == 2, (mod, path)


def test_store_roundtrip_names_only(tmp_path):
    s = Store(tmp_path / "t.db")
    cid = s.insert(Call(provider="ollama", model="m", tool_names=["read_file", "terminal"]))
    assert s.get(cid)["tool_names"] == ["read_file", "terminal"]
    raw = sqlite3.connect(tmp_path / "t.db").execute("SELECT * FROM calls").fetchall()
    assert "SECRET-DESC" not in repr(raw)


def test_store_migrates_old_db(tmp_path):
    db = tmp_path / "old.db"
    Store(db).db.close()
    c = sqlite3.connect(db)
    c.execute("ALTER TABLE calls DROP COLUMN tool_names")       # an existing database from before this change
    c.commit()
    c.close()
    assert "tool_names" not in [r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(calls)")]
    s = Store(db)                                                # reopening must add the column
    assert "tool_names" in [r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(calls)")]
    cid = s.insert(Call(provider="ollama", model="m", tool_names=["a"]))
    assert s.get(cid)["tool_names"] == ["a"]
    cid2 = s.insert(Call(provider="ollama", model="m"))
    assert s.get(cid2)["tool_names"] == []


def test_engine_passes_tool_names_through():
    assert "tool_names=parsed.tool_names" in inspect.getsource(engine.SightlineAddon)
