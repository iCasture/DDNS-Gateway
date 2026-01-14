import pytest
from fastapi.testclient import TestClient

from ddns_gateway.config import (
    AuthConfig,
    Config,
    HealthConfig,
)
from ddns_gateway.server import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
def mock_config_auth_enabled(monkeypatch):
    """Mock config with auth enabled and a valid token."""
    config = Config()
    config.auth = AuthConfig(enabled=True, tokens=["valid-token"])
    config.health = HealthConfig(enabled=True)

    def mock_get_config():
        return config

    monkeypatch.setattr("ddns_gateway.server.get_config", mock_get_config)
    monkeypatch.setattr("ddns_gateway.server._config", config)
    # Initialize app.state to avoid AttributeError
    app.state.dedupe_cache = None
    app.state.dedupe_config = None
    app.state.request_timeout_sec = 7.0
    return config


@pytest.fixture
def mock_config_auth_disabled(monkeypatch):
    """Mock config with auth disabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.health = HealthConfig(enabled=True)

    def mock_get_config():
        return config

    monkeypatch.setattr("ddns_gateway.server.get_config", mock_get_config)
    monkeypatch.setattr("ddns_gateway.server._config", config)
    # Initialize app.state to avoid AttributeError
    app.state.dedupe_cache = None
    app.state.dedupe_config = None
    app.state.request_timeout_sec = 7.0
    return config
