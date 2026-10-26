"""macOS integration: CA trust, PAC system proxy (with snapshot/restore), LaunchAgent.

Every change made here is reversible and recorded under the Sightline home so `uninstall`
can put the Mac back exactly as it was. Nothing here runs as root.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from .config import Settings

LOGIN_KEYCHAIN = Path.home() / "Library" / "Keychains" / "login.keychain-db"
AGENT_LABEL = "dev.sightline.agent"
AGENT_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{AGENT_LABEL}.plist"


def _run(*cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True, check=check)


# ----------------------------------------------------------------------------- CA

def ca_sha1(settings: Settings) -> str | None:
    if not settings.ca_cert.exists():
        return None
    der = ssl.PEM_cert_to_DER_cert(settings.ca_cert.read_text())
    return hashlib.sha1(der).hexdigest().upper()  # noqa: S324 - keychain identifies certs by SHA-1


def ca_trusted(settings: Settings) -> bool:
    if not settings.ca_cert.exists() or sys.platform != "darwin":
        return False
    r = _run("security", "verify-cert", "-c", str(settings.ca_cert), "-p", "ssl")
    return r.returncode == 0


def trust(settings: Settings) -> int:
    """Add the per-install CA to the LOGIN keychain, trusted for SSL only. Prompts for authorization."""
    return subprocess.call(["security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl",
                            "-k", str(LOGIN_KEYCHAIN), str(settings.ca_cert)])


def untrust(settings: Settings) -> bool:
    sha = ca_sha1(settings)
    if not sha:
        return False
    _run("security", "remove-trusted-cert", str(settings.ca_cert))
    r = _run("security", "delete-certificate", "-Z", sha, str(LOGIN_KEYCHAIN))
    return r.returncode == 0


def combined_bundle(settings: Settings) -> Path:
    """certifi roots + Sightline CA, for runtimes that ignore the keychain (Python, Node, curl)."""
    import certifi
    out = settings.home / "ca-bundle.pem"
    out.write_text(Path(certifi.where()).read_text() + "\n" + settings.ca_cert.read_text())
    os.chmod(out, 0o644)
    return out


# ----------------------------------------------------------------------------- PAC system proxy

def _services() -> list[str]:
    r = _run("networksetup", "-listallnetworkservices")
    return [ln.strip() for ln in r.stdout.splitlines()[1:] if ln.strip() and not ln.startswith("*")]


def proxy_on(settings: Settings) -> list[str]:
    backup = settings.home / "proxy-backup.json"
    snapshot = json.loads(backup.read_text()) if backup.exists() else {}
    url = f"http://127.0.0.1:{settings.ui_port}/proxy.pac"
    changed = []
    for svc in _services():
        if svc not in snapshot:
            cur = _run("networksetup", "-getautoproxyurl", svc).stdout
            snapshot[svc] = {"url": _field(cur, "URL"), "enabled": _field(cur, "Enabled") == "Yes"}
        if _run("networksetup", "-setautoproxyurl", svc, url).returncode == 0:
            changed.append(svc)
    backup.write_text(json.dumps(snapshot, indent=2))
    return changed


def proxy_off(settings: Settings) -> list[str]:
    backup = settings.home / "proxy-backup.json"
    if not backup.exists():
        return []
    restored = []
    for svc, prev in json.loads(backup.read_text()).items():
        if prev.get("url") and prev["url"] != "(null)":
            _run("networksetup", "-setautoproxyurl", svc, prev["url"])
        _run("networksetup", "-setautoproxystate", svc, "on" if prev.get("enabled") else "off")
        restored.append(svc)
    backup.unlink()
    return restored


def _field(text: str, name: str) -> str | None:
    for ln in text.splitlines():
        if ln.startswith(name + ":"):
            return ln.split(":", 1)[1].strip()
    return None


# ----------------------------------------------------------------------------- LaunchAgent

def service_install(settings: Settings, load: bool = True) -> Path:
    exe = shutil.which("sightline") or sys.argv[0]
    logs = Path.home() / "Library" / "Logs" / "Sightline"
    logs.mkdir(parents=True, exist_ok=True)
    AGENT_PLIST.parent.mkdir(parents=True, exist_ok=True)
    AGENT_PLIST.write_bytes(plistlib.dumps({
        "Label": AGENT_LABEL,
        "ProgramArguments": [exe, "start"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(logs / "sightline.log"),
        "StandardErrorPath": str(logs / "sightline.log"),
        "EnvironmentVariables": {"SIGHTLINE_HOME": str(settings.home)},
    }))
    if load:
        _run("launchctl", "bootstrap", f"gui/{os.getuid()}", str(AGENT_PLIST))
    return AGENT_PLIST


def service_uninstall() -> bool:
    if not AGENT_PLIST.exists():
        return False
    _run("launchctl", "bootout", f"gui/{os.getuid()}", str(AGENT_PLIST))
    AGENT_PLIST.unlink()
    return True
