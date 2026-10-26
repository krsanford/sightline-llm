import re

from sightline.app import mitm_options
from sightline.config import Settings


def test_every_reverse_target_is_in_allow_hosts():
    """Regression: a reverse-mode target missing from allow_hosts becomes an invisible raw TCP pipe."""
    opts = mitm_options(Settings())
    targets = [m.split(":", 1)[1].rsplit("@", 1)[0] for m in opts["mode"] if m.startswith("reverse:")]
    for t in targets:
        hostport = t.split("://", 1)[1]
        if ":" not in hostport:
            hostport += ":443" if t.startswith("https") else ":80"
        assert any(re.match(p, hostport) for p in opts["allow_hosts"]), hostport


def test_listeners_and_lazy_connections():
    opts = mitm_options(Settings())
    assert any(m.startswith("regular@") for m in opts["mode"]) and opts["connection_strategy"] == "lazy"
