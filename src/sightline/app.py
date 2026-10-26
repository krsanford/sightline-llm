"""Process entry: run the mitmproxy engine and the dashboard in one asyncio loop."""

from __future__ import annotations

import asyncio
import logging
import signal

import uvicorn
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .config import ALLOW_HOSTS_RE, Settings
from .engine import Bus, SightlineAddon
from .policy import Policy, write_default
from .pricing import load_table
from .server import create_app
from .store import Store

log = logging.getLogger("sightline")


async def serve(settings: Settings) -> None:
    settings.ensure()
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
    opts.update(
        mode=[f"regular@{settings.proxy_port}", f"reverse:https://api.openai.com@{settings.gateway_port}"],
        allow_hosts=[ALLOW_HOSTS_RE],
        connection_strategy="lazy",
    )
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
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(serve(settings or Settings.load()))
