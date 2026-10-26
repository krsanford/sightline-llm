"""SQLite storage for captured LLM calls.

Privacy floor (enforced here, not by callers):
- Only redacted text is ever written. Auth headers are never stored; a short SHA-256 fingerprint
  identifies "which key" without storing it.
- ``capture_bodies="metadata"`` stores no prompt/response text at all.
- Bodies are purged after ``body_retention_days``; rows after ``metadata_retention_days``.
- The database file is created 0600.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    id            INTEGER PRIMARY KEY,
    ts            REAL NOT NULL,
    mode          TEXT,             -- proxy | gateway
    client        TEXT,             -- user-agent derived app name
    provider      TEXT,
    host          TEXT,
    method        TEXT,
    path          TEXT,
    endpoint      TEXT,
    model         TEXT,
    stream        INTEGER,
    status        INTEGER,
    ttft_ms       REAL,
    latency_ms    REAL,
    input_tokens  INTEGER,
    output_tokens INTEGER,
    cache_read    INTEGER,
    cache_write   INTEGER,
    reasoning     INTEGER,
    usage_source  TEXT,
    usd           REAL,
    shadow_usd    REAL,
    action        TEXT,             -- allowed | redacted | blocked
    reasons       TEXT,             -- JSON list of policy reasons
    findings      TEXT,             -- JSON list of {kind, category, count}
    key_fp        TEXT,             -- sha256(auth)[:12], never the key
    tag           TEXT,             -- optional caller tag (e.g. X-Sightline-Tag: swarm/lane-a)
    prompt        TEXT,             -- redacted
    response      TEXT,             -- redacted
    error         TEXT,
    req_bytes     INTEGER,
    resp_bytes    INTEGER
);
CREATE INDEX IF NOT EXISTS calls_ts ON calls(ts);
CREATE INDEX IF NOT EXISTS calls_provider ON calls(provider, model);
"""

LIST_COLUMNS = ["id", "ts", "mode", "client", "provider", "host", "endpoint", "model", "stream", "status",
                "ttft_ms", "latency_ms", "input_tokens", "output_tokens", "cache_read", "usd", "shadow_usd",
                "action", "findings", "tag", "error", "usage_source"]


@dataclass
class Call:
    ts: float = field(default_factory=time.time)
    mode: str = "proxy"
    client: str | None = None
    provider: str | None = None
    host: str | None = None
    method: str | None = None
    path: str | None = None
    endpoint: str | None = None
    model: str | None = None
    stream: bool = False
    status: int | None = None
    ttft_ms: float | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read: int | None = None
    cache_write: int | None = None
    reasoning: int | None = None
    usage_source: str | None = None
    usd: float | None = None
    shadow_usd: float | None = None
    action: str = "allowed"
    reasons: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    key_fp: str | None = None
    tag: str | None = None
    prompt: str | None = None
    response: str | None = None
    error: str | None = None
    req_bytes: int | None = None
    resp_bytes: int | None = None


class Store:
    def __init__(self, path: Path, capture_bodies: str = "redacted"):
        self.path = Path(path)
        self.capture_bodies = capture_bodies
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        os.chmod(self.path, 0o600)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def insert(self, call: Call) -> int:
        d = asdict(call)
        if self.capture_bodies == "metadata":
            d["prompt"] = d["response"] = None
        d["reasons"] = json.dumps(d["reasons"])
        d["findings"] = json.dumps(d["findings"])
        d["stream"] = int(bool(d["stream"]))
        cols = ",".join(d)
        with self._lock:
            cur = self.db.execute(f"INSERT INTO calls({cols}) VALUES({','.join('?' * len(d))})",  # noqa: S608
                                  list(d.values()))
            return int(cur.lastrowid)

    def list(self, limit: int = 200, provider: str | None = None, since_id: int = 0) -> list[dict]:
        sql = f"SELECT {','.join(LIST_COLUMNS)} FROM calls WHERE id > ?"  # noqa: S608
        args: list = [since_id]
        if provider:
            sql += " AND provider = ?"
            args.append(provider)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(min(limit, 1000))
        with self._lock:
            rows = self.db.execute(sql, args).fetchall()
        return [_row(r) for r in rows]

    def get(self, call_id: int) -> dict | None:
        with self._lock:
            r = self.db.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
        return _row(r) if r else None

    def stats(self, since: float) -> dict:
        with self._lock:
            r = self.db.execute(
                """SELECT COUNT(*) n, COALESCE(SUM(input_tokens),0) tin, COALESCE(SUM(output_tokens),0) tout,
                          COALESCE(SUM(usd),0) usd, COALESCE(SUM(shadow_usd),0) shadow,
                          SUM(CASE WHEN action='redacted' THEN 1 ELSE 0 END) redacted,
                          SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) blocked,
                          SUM(CASE WHEN findings != '[]' THEN 1 ELSE 0 END) with_findings
                   FROM calls WHERE ts >= ?""", (since,)).fetchone()
            lat = [x[0] for x in self.db.execute(
                "SELECT latency_ms FROM calls WHERE ts >= ? AND latency_ms IS NOT NULL ORDER BY latency_ms",
                (since,)).fetchall()]
        out = dict(r)
        out["p50_ms"] = lat[len(lat) // 2] if lat else None
        out["p95_ms"] = lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else None
        return out

    def insights(self, since: float) -> dict:
        with self._lock:
            by_model = [dict(r) for r in self.db.execute(
                """SELECT provider, model, COUNT(*) calls, COALESCE(SUM(input_tokens),0) input_tokens,
                          COALESCE(SUM(output_tokens),0) output_tokens, COALESCE(SUM(usd),0) usd,
                          COALESCE(SUM(shadow_usd),0) shadow_usd, AVG(latency_ms) avg_latency_ms
                   FROM calls WHERE ts >= ? GROUP BY provider, model ORDER BY usd DESC, calls DESC""",
                (since,)).fetchall()]
            by_hour = [dict(r) for r in self.db.execute(
                """SELECT CAST(ts/3600 AS INTEGER)*3600 bucket, COUNT(*) calls,
                          COALESCE(SUM(usd),0)+COALESCE(SUM(shadow_usd),0) spend,
                          COALESCE(SUM(input_tokens),0)+COALESCE(SUM(output_tokens),0) tokens
                   FROM calls WHERE ts >= ? GROUP BY bucket ORDER BY bucket""", (since,)).fetchall()]
            by_client = [dict(r) for r in self.db.execute(
                """SELECT COALESCE(tag, client, 'unknown') client, COUNT(*) calls,
                          COALESCE(SUM(input_tokens),0)+COALESCE(SUM(output_tokens),0) tokens
                   FROM calls WHERE ts >= ? GROUP BY 1 ORDER BY calls DESC LIMIT 12""", (since,)).fetchall()]
            findings = {}
            for (f,) in self.db.execute("SELECT findings FROM calls WHERE ts >= ? AND findings != '[]'", (since,)):
                for item in json.loads(f):
                    findings[item["kind"]] = findings.get(item["kind"], 0) + item.get("count", 1)
        return {"by_model": by_model, "by_hour": by_hour, "by_client": by_client, "findings": findings}

    def tag_tokens_since(self, prefix: str, since: float) -> int:
        """Sum of input+output tokens for calls with ts >= since whose tag starts with ``prefix``.

        The prefix is matched literally with ``substr(tag, 1, len(prefix)) = prefix`` -- never LIKE,
        whose ``%`` and ``_`` are wildcards, and never GLOB. Untagged calls never match.
        """
        with self._lock:
            r = self.db.execute(
                "SELECT COALESCE(SUM(COALESCE(input_tokens,0)+COALESCE(output_tokens,0)),0) t FROM calls "
                "WHERE ts >= ? AND tag IS NOT NULL AND substr(tag, 1, ?) = ?",
                (since, len(prefix), prefix),
            ).fetchone()
        return int(r[0]) if r else 0

    def purge(self, body_days: int, metadata_days: int, now: float | None = None) -> tuple[int, int]:
        now = now or time.time()
        with self._lock:
            b = self.db.execute("UPDATE calls SET prompt=NULL, response=NULL WHERE ts < ? AND "
                                "(prompt IS NOT NULL OR response IS NOT NULL)", (now - body_days * 86400,)).rowcount
            m = self.db.execute("DELETE FROM calls WHERE ts < ?", (now - metadata_days * 86400,)).rowcount
        return b, m

    def clear(self) -> None:
        with self._lock:
            self.db.execute("DELETE FROM calls")


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("reasons", "findings"):
        if isinstance(d.get(k), str):
            d[k] = json.loads(d[k])
    if "stream" in d:
        d["stream"] = bool(d["stream"])
    return d
