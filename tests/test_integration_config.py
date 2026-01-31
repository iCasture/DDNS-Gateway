"""Integration tests for configuration loading and endpoint behavior."""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ddns_gateway.config import load_config, parse_args
from ddns_gateway.server import create_app


def test_config_to_endpoint_integration():
    """
    Test the full flow from TOML file to FastAPI endpoint behavior.

    This ensures that values parsed by tomllib are correctly propagated
    through the app state to the endpoints and middleware.
    """
    toml_content = """
[server]
host = "127.0.0.1"
port = 9999

[auth]
enabled = true
tokens = ["integration-test-token"]

[response]
include_debug_info = true

[health]
enabled = true
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        config_path = Path(f.name)

    try:
        # 1. Load config using the actual logic from cli.py
        args = parse_args(["--config", str(config_path)])
        config = load_config(args)

        # Verify config object matches TOML
        assert config.server.port == 9999
        assert config.auth.enabled is True
        assert "integration-test-token" in config.auth.tokens
        assert config.response.include_debug_info is True
        assert config.health.enabled is True

        # 2. Create app with this config
        app = create_app(config)

        # 3. Test behavior via TestClient
        with TestClient(app) as client:
            # Test Auth (should be enabled)
            resp = client.put(
                "/v1/ddns/cloudflare/example.com/A/home", json={"value": "1.1.1.1"}
            )
            assert resp.status_code == 401  # Missing token

            # Test Auth with valid token from TOML
            resp = client.put(
                "/v1/ddns/cloudflare/example.com/A/home",
                json={"value": "1.1.1.1"},
                headers={"Authorization": "Bearer integration-test-token"},
            )
            # Should not be 401 (gateway auth error)
            # 403 is acceptable - it indicates upstream auth failure, meaning gateway auth passed
            assert resp.status_code != 401

            # Test Debug Info (should be enabled)
            # We expect 'debug' field in response even if it's an error (like missing provider credentials)
            data = resp.json()
            assert "debug" in data
            assert data["debug"] is not None
            assert data["debug"]["raw_input"]["value"] == "1.1.1.1"

            # Test Health endpoint (should be enabled)
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}

    finally:
        if config_path.exists():
            config_path.unlink()


def test_config_cli_override_integration():
    """Test that CLI overrides work correctly when passing to the app."""
    toml_content = """
[server]
port = 8888
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        config_path = Path(f.name)

    try:
        # Override port via CLI
        args = parse_args(["--config", str(config_path), "--port", "7777"])
        config = load_config(args)

        assert config.server.port == 7777  # CLI takes precedence

        app = create_app(config)
        # In a real run, uvicorn would use config.server.port
        with TestClient(app):
            assert app.state.config.server.port == 7777

    finally:
        if config_path.exists():
            config_path.unlink()
