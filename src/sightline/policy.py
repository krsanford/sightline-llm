"""Policy: what Sightline does to a request before it leaves the Mac.

    # ~/Library/Application Support/Sightline/policy.yaml
    redact:
      categories: [secret, pii]   # mask these in request bodies before forwarding
      on_secret: redact           # redact | block
    block:
      - {provider: deepseek, reason: "Not approved for company data"}
      - {model: "gpt-6-astra*", reason: "Use gpt-6-sol for routine work"}

Redaction walks every JSON string value in the body and masks findings in place, so the request
stays valid for any provider schema. Every decision carries human-readable reasons, which the UI shows.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger("sightline.policy")

DEFAULT_POLICY = {
    "redact": {"categories": ["secret", "pii"], "on_secret": "redact"},
    "block": [{"provider": "deepseek", "reason": "Example policy: provider not approved for company data"}],
}


def write_default(path: Path) -> None:
    if not path.exists():
        header = "# Sightline policy. Edit and restart Sightline.\n"
        path.write_text(header + yaml.safe_dump(DEFAULT_POLICY, sort_keys=False))


def _detector():
    try:
        from . import detect
        return detect
    except Exception as exc:  # noqa: BLE001 - detection is optional until the module exists
        log.warning("detect module unavailable, redaction disabled: %s", exc)
        return None


@dataclass
class Decision:
    action: str = "allowed"                  # allowed | redacted | blocked
    reasons: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)   # [{kind, category, count}]
    body: bytes | None = None                # rewritten body when action == "redacted"


@dataclass
class Policy:
    categories: set[str] = field(default_factory=lambda: {"secret", "pii"})
    on_secret: str = "redact"
    blocks: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> Policy:
        data = DEFAULT_POLICY
        if path and Path(path).exists():
            data = yaml.safe_load(Path(path).read_text()) or DEFAULT_POLICY
        red = data.get("redact") or {}
        return cls(categories=set(red.get("categories", ["secret", "pii"])),
                   on_secret=red.get("on_secret", "redact"),
                   blocks=list(data.get("block") or []))

    def to_dict(self) -> dict:
        return {"redact": {"categories": sorted(self.categories), "on_secret": self.on_secret},
                "block": self.blocks}

    def check_block(self, provider: str | None, model: str | None, host: str | None) -> str | None:
        for rule in self.blocks:
            if "provider" in rule and rule["provider"] != provider:
                continue
            if "model" in rule and not (model and fnmatch.fnmatch(model.lower(), str(rule["model"]).lower())):
                continue
            if "host" in rule and not (host and fnmatch.fnmatch(host, rule["host"])):
                continue
            return rule.get("reason") or "blocked by policy"
        return None

    def evaluate(self, provider: str | None, model: str | None, host: str | None, body: bytes) -> Decision:
        reason = self.check_block(provider, model, host)
        if reason:
            return Decision(action="blocked", reasons=[reason])
        det = _detector()
        if det is None or not body:
            return Decision()
        try:
            doc = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return Decision()
        counts: Counter = Counter()
        categories: dict[str, str] = {}

        def walk(node):
            if isinstance(node, str):
                out, found = det.redact(node, categories=self.categories)
                for f in found:
                    counts[f.kind] += 1
                    categories[f.kind] = f.category
                return out
            if isinstance(node, list):
                return [walk(x) for x in node]
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            return node

        new_doc = walk(doc)
        findings = [{"kind": k, "category": categories[k], "count": n} for k, n in sorted(counts.items())]
        if not findings:
            return Decision()
        has_secret = any(f["category"] == "secret" for f in findings)
        summary = ", ".join(f"{f['count']}× {f['kind']}" for f in findings)
        if has_secret and self.on_secret == "block":
            return Decision(action="blocked", reasons=[f"secret in prompt ({summary})"], findings=findings)
        return Decision(action="redacted", reasons=[f"masked before forwarding: {summary}"], findings=findings,
                        body=json.dumps(new_doc, ensure_ascii=False).encode())


def redact_text(text: str | None, categories: set[str] | None = None) -> str | None:
    """Redact free text for storage (defense in depth: storage never holds raw secrets)."""
    if not text:
        return text
    det = _detector()
    if det is None:
        return text
    out, _ = det.redact(text, categories=categories or {"secret", "pii"})
    return out
