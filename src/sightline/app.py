"""Process entry: run the mitmproxy engine and the dashboard in one asyncio loop."""

from __future__ import annotations

import asyncio
import logging
import re
import signal

import uvicorn
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .ca import ensure_ca
from .config import ALLOW_HOSTS_RE, Settings
from .engine import Bus, SightlineAddon
from .policy import Policy, write_default
from .pricing import load_table
from .server import create_app
from .store import Store

log = logging.getLogger("sightline")


def mitm_options(settings: Settings) -> dict:
    """mitmproxy listener options. Kept separate so the wiring is unit-tested."""
    return {
        "mode": [f"regular@{settings.proxy_port}", f"reverse:https://api.openai.com@{settings.gateway_port}",
                 f"reverse:http://{settings.ollama_upstream[0]}:{settings.ollama_upstream[1]}@{settings.ollama_port}"],
        # allow_hosts also gates reverse-mode targets: without the Ollama entry, the transparent Ollama listener
        # silently degrades to a raw TCP pipe the addon never sees. (Proxy mode still refuses private upstreams.)
        "allow_hosts": [ALLOW_HOSTS_RE, rf"^{re.escape(settings.ollama_upstream[0])}:{settings.ollama_upstream[1]}$"],
        "connection_strategy": "lazy",
    }


async def serve(settings: Settings) -> None:
    settings.ensure()
    if ensure_ca(settings.certs_dir):
        log.info("created name-constrained CA in %s", settings.certs_dir)
    store = Store(settings.db_path, capture_bodies=settings.capture_bodies)
    purged = store.purge(settings.body_retention_days, settings.metadata_retention_days)
    if any(purged):
        log.info("retention purge: %d bodies cleared, %d rows deleted", *purged)
    write_default(settings.policy_path)
    policy = Policy.load(settings.policy_path)
    bus = Bus()

    opts = Options(listen_host="127.0.0.1", confdir=str(settings.certs_dir))
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    # These options are registered by mitmproxy's addons, so they can only be set once the master exists.
    opts.update(**mitm_options(settings))
    master.addons.add(SightlineAddon(settings, store, policy, load_table(), bus))

    app = create_app(settings, store, policy, bus)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=settings.ui_port, log_level="warning",
                                           access_log=False))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: (master.shutdown(), setattr(server, "should_exit", True)))

    async def purge_loop():
        while True:
            await asyncio.sleep(3600)
            store.purge(settings.body_retention_days, settings.metadata_retention_days)

    purger = asyncio.create_task(purge_loop())
    try:
        await asyncio.gather(master.run(), server.serve())
    finally:
        purger.cancel()


def run(settings: Settings | None = None) -> None:
    import os
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if os.environ.get("SIGHTLINE_DEBUG"):
        logging.getLogger("sightline").setLevel(logging.DEBUG)
    asyncio.run(serve(settings or Settings.load()))
