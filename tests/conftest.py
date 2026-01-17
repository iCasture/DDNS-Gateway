"""
Pytest fixtures for DDNS Gateway tests.

This module provides common fixtures used across test modules.
"""

import pytest
from fastapi.testclient import TestClient

from ddns_gateway.config import (
    AuthConfig,
    Config,
    DedupeConfig,
    HealthConfig,
    ResponseConfig,
    RetryConfig,
)
from ddns_gateway.server import create_app


@pytest.fixture
def default_config() -> Config:
    """Create a default configuration for testing."""
    return Config()


@pytest.fixture
def config_auth_enabled() -> Config:
    """Create a configuration with auth enabled."""
    config = Config()
    config.auth = AuthConfig(enabled=True, tokens=["valid-token"])
    config.health = HealthConfig(enabled=True)
    return config


@pytest.fixture
def config_auth_disabled() -> Config:
    """Create a configuration with auth disabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.health = HealthConfig(enabled=True)
    return config


@pytest.fixture
def config_debug_enabled() -> Config:
    """Create a configuration with debug info enabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.response = ResponseConfig(include_debug_info=True)
    return config


@pytest.fixture
def config_dedupe_disabled() -> Config:
    """Create a configuration with dedupe disabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.dedupe = DedupeConfig(enabled=False)
    return config


@pytest.fixture
def app_auth_enabled(config_auth_enabled: Config):
    """Create a test app with auth enabled."""
    return create_app(config_auth_enabled)


@pytest.fixture
def app_auth_disabled(config_auth_disabled: Config):
    """Create a test app with auth disabled."""
    return create_app(config_auth_disabled)


@pytest.fixture
def app_debug_enabled(config_debug_enabled: Config):
    """Create a test app with debug info enabled."""
    return create_app(config_debug_enabled)


@pytest.fixture
def client_auth_enabled(app_auth_enabled):
    """Create a test client with auth enabled."""
    with TestClient(app_auth_enabled) as client:
        yield client


@pytest.fixture
def client_auth_disabled(app_auth_disabled):
    """Create a test client with auth disabled."""
    with TestClient(app_auth_disabled) as client:
        yield client


@pytest.fixture
def client_debug_enabled(app_debug_enabled):
    """Create a test client with debug info enabled."""
    with TestClient(app_debug_enabled) as client:
        yield client


# Legacy fixtures for backwards compatibility with existing tests
# These will be deprecated in favor of the new fixtures above


@pytest.fixture
def client(app_auth_disabled):
    """
    Create a test client with default configuration.

    This is a legacy fixture for backwards compatibility.
    Prefer using client_auth_disabled or client_auth_enabled.
    """
    with TestClient(app_auth_disabled) as client:
        yield client


@pytest.fixture
def mock_config_auth_enabled(config_auth_enabled: Config, monkeypatch):
    """
    Mock config with auth enabled and a valid token.

    This fixture creates a test app with auth enabled and patches it
    for use with the default client fixture.

    Note: This is a legacy fixture. Prefer using client_auth_enabled directly.
    """
    app = create_app(config_auth_enabled)
    # Patch the default client to use this app
    monkeypatch.setattr("tests.conftest.app_auth_disabled", lambda: app)
    return config_auth_enabled


@pytest.fixture
def mock_config_auth_disabled(config_auth_disabled: Config):
    """
    Mock config with auth disabled.

    Note: This is a legacy fixture. Prefer using client_auth_disabled directly.
    """
    return config_auth_disabled
