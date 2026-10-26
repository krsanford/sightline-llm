"""foundry preflight (cycle 3, W5): /api/setup reports the inference allowlist and the num_ctx pin it enforces."""
from fastapi.testclient import TestClient

from sightline.config import Settings
from sightline.engine import Bus
from sightline.policy import Policy
from sightline.server import create_app
from sightline.store import Store


def _setup(tmp_path, **kw):
    s = Settings(home=tmp_path, **kw)
    app = create_app(s, Store(tmp_path / "t.db"), Policy(), Bus())
    return TestClient(app, base_url=f"http://127.0.0.1:{s.ui_port}").get("/api/setup").json()


def test_setup_exposes_allow_models_and_pin_num_ctx(tmp_path):
    out = _setup(tmp_path, allow_models=["qwen3.8:27b-mlx-256k", "gemma4:26b-mlx"], pin_num_ctx=65536)
    assert out["allow_models"] == ["gemma4:26b-mlx", "qwen3.8:27b-mlx-256k"]
    assert out["pin_num_ctx"] == 65536


def test_setup_defaults(tmp_path):
    out = _setup(tmp_path)
    assert out["allow_models"] == [] and out["pin_num_ctx"] == 262144


def test_setup_pin_disabled(tmp_path):
    assert _setup(tmp_path, pin_num_ctx=None)["pin_num_ctx"] is None
