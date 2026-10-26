"""sightline — see every LLM call your Mac makes."""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import urllib.request
import webbrowser

from . import __version__, macos
from .config import Settings

DIM, BOLD, GREEN, RED, YELLOW, RESET = "\033[2m", "\033[1m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def bad(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


def note(msg: str) -> None:
    print(f"  {DIM}{msg}{RESET}")


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ----------------------------------------------------------------------------- commands

def cmd_start(s: Settings, args) -> int:
    from .app import run
    s.ensure()
    print(f"{BOLD}Sightline {__version__}{RESET}")
    print(f"  dashboard   http://127.0.0.1:{s.ui_port}")
    print(f"  proxy       127.0.0.1:{s.proxy_port}   (eval \"$(sightline env)\")")
    print(f"  gateway     http://127.0.0.1:{s.gateway_port}/{{openai,anthropic,gemini,ollama}}")
    print(f"  data        {s.home}\n")
    if args.open:
        webbrowser.open(f"http://127.0.0.1:{s.ui_port}")
    run(s)
    return 0


def cmd_open(s: Settings, _args) -> int:
    webbrowser.open(f"http://127.0.0.1:{s.ui_port}")
    return 0


def cmd_env(s: Settings, args) -> int:
    if args.gateway:
        print(f"export OPENAI_BASE_URL=http://127.0.0.1:{s.gateway_port}/openai/v1")
        print(f"export ANTHROPIC_BASE_URL=http://127.0.0.1:{s.gateway_port}/anthropic")
        print(f"export OLLAMA_HOST=http://127.0.0.1:{s.gateway_port}/ollama")
        return 0
    if not s.ca_cert.exists():
        print("# Sightline has not generated its CA yet: run `sightline start` once.", file=sys.stderr)
        return 1
    bundle = macos.combined_bundle(s)
    print(f"export HTTPS_PROXY=http://127.0.0.1:{s.proxy_port}")
    print(f"export https_proxy=http://127.0.0.1:{s.proxy_port}")
    print("export NODE_USE_ENV_PROXY=1")
    print(f"export NODE_EXTRA_CA_CERTS={s.ca_cert}")
    print(f"export SSL_CERT_FILE={bundle}")
    print(f"export REQUESTS_CA_BUNDLE={bundle}")
    print(f"export CURL_CA_BUNDLE={bundle}")
    return 0


def cmd_trust(s: Settings, _args) -> int:
    if not s.ca_cert.exists():
        bad("No CA yet — run `sightline start` once first.")
        return 1
    print(f"{BOLD}Trust the Sightline CA{RESET}\n")
    note("This adds a certificate unique to this Mac to your LOGIN keychain, trusted for SSL only.")
    note("Sightline uses it to decrypt traffic to LLM API hosts — and nothing else; all other")
    note("traffic is tunneled untouched. macOS will ask for your password. Undo: `sightline untrust`.\n")
    rc = macos.trust(s)
    (ok if rc == 0 else bad)("CA trusted" if rc == 0 else "CA not trusted")
    return rc


def cmd_untrust(s: Settings, _args) -> int:
    if macos.untrust(s):
        ok("CA removed from login keychain")
    else:
        note("CA was not in the login keychain")
    return 0


def cmd_proxy(s: Settings, args) -> int:
    if args.state == "on":
        changed = macos.proxy_on(s)
        ok(f"PAC proxy set on: {', '.join(changed) or 'no services'}")
        note("Only LLM API hosts are routed to Sightline; if it stops, macOS falls back to DIRECT.")
    else:
        restored = macos.proxy_off(s)
        ok(f"proxy settings restored: {', '.join(restored) or 'nothing to restore'}")
    return 0


def cmd_status(s: Settings, _args) -> int:
    up = _listening(s.ui_port)
    print(f"{BOLD}Sightline{RESET} {'running' if up else 'stopped'}")
    if up:
        st = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{s.ui_port}/api/stats").read())  # noqa: S310
        print(f"  last 24h: {st['n']} calls · {st['tin'] + st['tout']:,} tokens · ${st['usd']:.4f}"
              f" (+${st['shadow']:.4f} shadow) · {st['redacted'] or 0} redacted · {st['blocked'] or 0} blocked")
    return 0


def cmd_doctor(s: Settings, _args) -> int:
    print(f"{BOLD}Sightline doctor{RESET}")
    fails = 0
    for name, port in (("dashboard", s.ui_port), ("proxy", s.proxy_port), ("gateway", s.gateway_port)):
        if _listening(port):
            ok(f"{name} listening on 127.0.0.1:{port}")
        else:
            bad(f"{name} not listening on 127.0.0.1:{port} — run `sightline start`")
            fails += 1
    if s.ca_cert.exists():
        ok(f"CA present ({s.ca_cert})")
        if macos.ca_trusted(s):
            ok("CA trusted in keychain (Safari, Chrome, Electron apps, Go/Swift clients)")
        else:
            note("CA not trusted in keychain — GUI apps won't be captured in proxy mode. Fix: `sightline trust`")
    else:
        note("CA not generated yet (created on first `sightline start`)")
    if not _listening(s.proxy_port) or not s.ca_cert.exists():
        return 1
    bundle = macos.combined_bundle(s)
    # Canary per client class: does a request to api.openai.com through the proxy get decrypted?
    curl = shutil.which("curl")
    if curl:
        r = subprocess.run([curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", "-x",
                            f"http://127.0.0.1:{s.proxy_port}", "--cacert", str(bundle),
                            "-H", "X-Sightline-Tag: doctor/curl", "https://api.openai.com/v1/models"],
                           capture_output=True, text=True)
        (ok if r.stdout in ("401", "200") else bad)(f"curl via proxy → api.openai.com: HTTP {r.stdout or 'error'}")
    py = subprocess.run([sys.executable, "-c",
                         "import httpx,sys;r=httpx.get('https://api.openai.com/v1/models',"
                         f"proxy='http://127.0.0.1:{s.proxy_port}',verify=sys.argv[1],"
                         "headers={'X-Sightline-Tag':'doctor/python'},timeout=10);print(r.status_code)", str(bundle)],
                        capture_output=True, text=True)
    (ok if py.stdout.strip() in ("401", "200") else note)(
        f"python httpx via proxy: {py.stdout.strip() or py.stderr.strip().splitlines()[-1:] or 'n/a'}")
    node = shutil.which("node")
    if node:
        nd = subprocess.run([node, "-e", "fetch('https://api.openai.com/v1/models',{headers:{'X-Sightline-Tag':"
                             "'doctor/node'}}).then(r=>console.log(r.status)).catch(e=>console.log('ERR',e.cause?.code))"],
                            capture_output=True, text=True, timeout=20,
                            env={"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HTTPS_PROXY":
                                 f"http://127.0.0.1:{s.proxy_port}", "NODE_USE_ENV_PROXY": "1",
                                 "NODE_EXTRA_CA_CERTS": str(s.ca_cert)})
        (ok if nd.stdout.strip() in ("401", "200") else note)(
            f"node fetch via proxy (NODE_USE_ENV_PROXY=1): {nd.stdout.strip() or 'n/a'}")
    return 1 if fails else 0


def cmd_demo(s: Settings, _args) -> int:
    from .demo import run_demo
    return run_demo(s)


def cmd_uninstall(s: Settings, args) -> int:
    print(f"{BOLD}Uninstalling Sightline{RESET}")
    restored = macos.proxy_off(s)
    ok(f"system proxy restored ({', '.join(restored) or 'was not enabled'})")
    if macos.untrust(s):
        ok("CA removed from login keychain")
    else:
        ok("CA was not in keychain")
    if macos.service_uninstall():
        ok("LaunchAgent removed")
    else:
        ok("no LaunchAgent installed")
    if s.certs_dir.exists():
        shutil.rmtree(s.certs_dir)
        ok("CA private key deleted")
    if args.yes or input(f"  Delete captured data in {s.home}? [y/N] ").strip().lower() == "y":
        shutil.rmtree(s.home, ignore_errors=True)
        ok("data deleted")
    else:
        note(f"data kept in {s.home}")
    note("Finally: `uv tool uninstall sightline-llm`")
    return 0


def cmd_service(s: Settings, args) -> int:
    if args.action == "install":
        ok(f"LaunchAgent installed: {macos.service_install(s)}")
    else:
        (ok if macos.service_uninstall() else note)("LaunchAgent removed")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sightline", description=__doc__)
    p.add_argument("--version", action="version", version=f"sightline {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("start", help="run the proxy, gateway and dashboard")
    st.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    sub.add_parser("open", help="open the dashboard")
    ev = sub.add_parser("env", help="print shell exports that route a terminal through Sightline")
    ev.add_argument("--gateway", action="store_true", help="base-URL exports instead of proxy + CA")
    sub.add_parser("trust", help="trust the Sightline CA in the login keychain (asks for password)")
    sub.add_parser("untrust", help="remove the CA from the keychain")
    pr = sub.add_parser("proxy", help="route LLM hosts system-wide via a PAC file")
    pr.add_argument("state", choices=["on", "off"])
    sub.add_parser("status", help="is it running, and what has it seen")
    sub.add_parser("doctor", help="check each capture path with a canary request")
    sub.add_parser("demo", help="send a scripted set of requests so the dashboard has real data")
    un = sub.add_parser("uninstall", help="restore proxy settings, remove CA, LaunchAgent and data")
    un.add_argument("--yes", action="store_true")
    sv = sub.add_parser("service", help="start at login (user LaunchAgent)")
    sv.add_argument("action", choices=["install", "uninstall"])
    args = p.parse_args(argv)
    s = Settings.load()
    handler = {"start": cmd_start, "open": cmd_open, "env": cmd_env, "trust": cmd_trust, "untrust": cmd_untrust,
               "proxy": cmd_proxy, "status": cmd_status, "doctor": cmd_doctor, "demo": cmd_demo,
               "uninstall": cmd_uninstall, "service": cmd_service}[args.cmd]
    return handler(s, args)


if __name__ == "__main__":
    sys.exit(main())
