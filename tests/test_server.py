"""Tests for server authentication, method validation, and error handling."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette import status as st_status

from ddns_gateway.config import (
    AuthConfig,
    Config,
    HealthConfig,
    MethodsConfig,
    ServerConfig,
)
from ddns_gateway.server import app, lifespan, parse_upstream_auth


# Fixtures for config manipulation
@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
def mock_config_auth_enabled(monkeypatch):
    """Mock config with auth enabled and a valid token."""
    config = Config()
    config.auth = AuthConfig(enabled=True, tokens=["valid-token"])
    config.methods = MethodsConfig(get_enabled=True, post_enabled=True)
    config.health = HealthConfig(enabled=True)

    def mock_get_config():
        return config

    monkeypatch.setattr("ddns_gateway.server.get_config", mock_get_config)
    monkeypatch.setattr("ddns_gateway.server._config", config)
    return config


@pytest.fixture
def mock_config_auth_disabled(monkeypatch):
    """Mock config with auth disabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.methods = MethodsConfig(get_enabled=True, post_enabled=True)
    config.health = HealthConfig(enabled=True)

    def mock_get_config():
        return config

    monkeypatch.setattr("ddns_gateway.server.get_config", mock_get_config)
    monkeypatch.setattr("ddns_gateway.server._config", config)
    return config


@pytest.fixture
def mock_config_get_disabled(monkeypatch):
    """Mock config with GET method disabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.methods = MethodsConfig(get_enabled=False, post_enabled=True)

    def mock_get_config():
        return config

    monkeypatch.setattr("ddns_gateway.server.get_config", mock_get_config)
    monkeypatch.setattr("ddns_gateway.server._config", config)
    return config


@pytest.fixture
def mock_config_post_disabled(monkeypatch):
    """Mock config with POST method disabled."""
    config = Config()
    config.auth = AuthConfig(enabled=False, tokens=[])
    config.methods = MethodsConfig(get_enabled=True, post_enabled=False)

    def mock_get_config():
        return config

    monkeypatch.setattr("ddns_gateway.server.get_config", mock_get_config)
    monkeypatch.setattr("ddns_gateway.server._config", config)
    return config


class TestAuthMiddleware:
    """Tests for authentication middleware using Authorization header."""

    def test_missing_token_returns_401(self, client, mock_config_auth_enabled):
        """Test that missing Authorization header returns 401."""
        response = client.get(
            "/update",
            params={
                "provider": "cloudflare",
                "zone": "example.com",
                "record": "home",
                "type": "A",
                "value": "1.2.3.4",
            },
        )

        assert response.status_code == st_status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert data["status"] == "error"
        assert data["code"] == st_status.HTTP_401_UNAUTHORIZED
        assert data["message"] == "Missing authentication token"

    def test_invalid_token_returns_403(self, client, mock_config_auth_enabled):
        """Test that invalid Bearer token returns 403."""
        response = client.get(
            "/update",
            params={
                "provider": "cloudflare",
                "zone": "example.com",
                "record": "home",
                "type": "A",
                "value": "1.2.3.4",
            },
            headers={"Authorization": "Bearer invalid-token"},
        )

        assert response.status_code == st_status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["status"] == "error"
        assert data["code"] == st_status.HTTP_403_FORBIDDEN
        assert data["message"] == "Invalid authentication token"

    def test_valid_token_passes_auth(self, client, mock_config_auth_enabled):
        """Test that valid Bearer token passes authentication (may fail at provider)."""
        response = client.get(
            "/update",
            params={
                "provider": "cloudflare",
                "zone": "example.com",
                "record": "home",
                "type": "A",
                "value": "1.2.3.4",
            },
            headers={"Authorization": "Bearer valid-token"},
        )

        # Should not be 401/403 - may be 400 due to missing provider credentials
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]

    def test_auth_disabled_allows_request(self, client, mock_config_auth_disabled):
        """Test that auth disabled allows request without Authorization header."""
        response = client.get(
            "/update",
            params={
                "provider": "cloudflare",
                "zone": "example.com",
                "record": "home",
                "type": "A",
                "value": "1.2.3.4",
            },
        )

        # Should not be 401/403
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]

    def test_bearer_token_case_insensitive(self, client, mock_config_auth_enabled):
        """Test that 'bearer' prefix is case-insensitive."""
        response = client.get(
            "/update",
            params={
                "provider": "cloudflare",
                "zone": "example.com",
                "record": "home",
                "type": "A",
                "value": "1.2.3.4",
            },
            headers={"Authorization": "BEARER valid-token"},
        )

        # Should not be 401/403
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]


class TestMethodMiddleware:
    """Tests for HTTP method validation middleware."""

    def test_get_disabled_returns_405(self, client, mock_config_get_disabled):
        """Test that disabled GET method returns 405."""
        response = client.get("/update")

        assert response.status_code == st_status.HTTP_405_METHOD_NOT_ALLOWED
        data = response.json()
        assert data["status"] == "error"
        assert data["code"] == st_status.HTTP_405_METHOD_NOT_ALLOWED
        assert data["message"] == "GET method is disabled"

    def test_post_disabled_returns_405(self, client, mock_config_post_disabled):
        """Test that disabled POST method returns 405."""
        response = client.post(
            "/update",
            json={
                "provider": "cloudflare",
                "zone": "example.com",
                "record": "home",
                "type": "A",
                "value": "1.2.3.4",
            },
        )

        assert response.status_code == st_status.HTTP_405_METHOD_NOT_ALLOWED
        data = response.json()
        assert data["status"] == "error"
        assert data["code"] == st_status.HTTP_405_METHOD_NOT_ALLOWED
        assert data["message"] == "POST method is disabled"


class TestValidationErrorHandler:
    """Tests for validation error handling."""

    def test_missing_params_returns_422(self, client, mock_config_auth_disabled):
        """Test that missing parameters returns 422 with clear message."""
        response = client.get("/update")

        assert response.status_code == st_status.HTTP_422_UNPROCESSABLE_CONTENT
        data = response.json()
        assert data["status"] == "error"
        assert data["code"] == st_status.HTTP_422_UNPROCESSABLE_CONTENT
        assert "Missing required fields" in data["message"]
        # Check that missing fields are listed
        assert "provider" in data["message"]
        assert "zone" in data["message"]
        assert "record" in data["message"]
        assert "type" in data["message"]
        assert "value" in data["message"]

    def test_partial_params_lists_missing(self, client, mock_config_auth_disabled):
        """Test that partial parameters correctly lists only missing ones."""
        response = client.get(
            "/update",
            params={
                "provider": "cloudflare",
                "zone": "example.com",
            },
        )

        assert response.status_code == st_status.HTTP_422_UNPROCESSABLE_CONTENT
        data = response.json()
        assert data["status"] == "error"
        assert data["code"] == st_status.HTTP_422_UNPROCESSABLE_CONTENT
        assert "Missing required fields" in data["message"]
        # These should be listed as missing
        assert "record" in data["message"]
        assert "type" in data["message"]
        assert "value" in data["message"]
        # These should NOT be listed as missing (they were provided)
        assert (
            "provider" not in data["message"]
            or "Missing required fields: " not in data["message"].split("provider")[0]
        )


class TestHealthEndpoint:
    """Tests for health check endpoint.

    Since the /health route is dynamically registered based on config during
    lifespan startup, each test needs to create a fresh FastAPI app instance
    with the lifespan context manager to ensure the route is registered.
    """

    def test_health_bypasses_auth(self, monkeypatch):
        """Test that health endpoint bypasses authentication."""
        # Create config with health enabled and auth enabled
        config = Config()
        config.server = ServerConfig()
        config.health = HealthConfig(enabled=True)
        config.methods = MethodsConfig(get_enabled=True, post_enabled=True)
        config.auth = AuthConfig(enabled=True, tokens=["valid-token"])

        # Set the config before creating the app
        monkeypatch.setattr("ddns_gateway.server._config", config)

        # Create a fresh app with the lifespan that registers /health
        test_app = FastAPI(lifespan=lifespan)

        # Use context manager to ensure lifespan events are triggered
        with TestClient(test_app) as test_client:
            # Health endpoint should be accessible without authentication
            response = test_client.get("/health")

            assert response.status_code == st_status.HTTP_200_OK
            assert response.json() == {"status": "ok"}

    def test_health_disabled_returns_404(self, monkeypatch):
        """Test that disabled health endpoint returns 404."""
        # Create config with health disabled
        config = Config()
        config.server = ServerConfig()
        config.health = HealthConfig(enabled=False)
        config.methods = MethodsConfig(get_enabled=True, post_enabled=True)
        config.auth = AuthConfig(enabled=False, tokens=[])

        # Set the config before creating the app
        monkeypatch.setattr("ddns_gateway.server._config", config)

        # Create a fresh app with the lifespan that checks health.enabled
        test_app = FastAPI(lifespan=lifespan)

        # Use context manager to ensure lifespan events are triggered
        with TestClient(test_app) as test_client:
            response = test_client.get("/health")

            assert response.status_code == st_status.HTTP_404_NOT_FOUND


class TestUpstreamAuthHeader:
    """Tests for X-Upstream-Authorization header parsing."""

    def test_parse_with_id_and_secret(self):
        """Test parsing header with both id and secret."""
        auth_id, auth_secret = parse_upstream_auth(
            'ApiKey id="myid", secret="mysecret"',
        )
        assert auth_id == "myid"
        assert auth_secret == "mysecret"

    def test_parse_with_secret_only(self):
        """Test parsing header with secret only (for Cloudflare)."""
        auth_id, auth_secret = parse_upstream_auth('ApiKey secret="cf-token-xxx"')
        assert auth_id is None
        assert auth_secret == "cf-token-xxx"

    def test_parse_case_insensitive(self):
        """Test that ApiKey is case-insensitive."""
        auth_id, auth_secret = parse_upstream_auth('APIKEY id="id1", secret="sec1"')
        assert auth_id == "id1"
        assert auth_secret == "sec1"

    def test_parse_invalid_format(self):
        """Test that invalid format returns None, None."""
        auth_id, auth_secret = parse_upstream_auth("invalid-header")
        assert auth_id is None
        assert auth_secret is None

    def test_parse_empty_string(self):
        """Test that empty string returns None, None."""
        auth_id, auth_secret = parse_upstream_auth("")
        assert auth_id is None
        assert auth_secret is None

    @pytest.mark.parametrize(
        ("header", "expected_id", "expected_secret"),
        [
            # Double quotes - id first
            ('ApiKey   id="myid", secret="mysecret"', "myid", "mysecret"),
            # Double quotes - secret first
            ('ApiKey   secret="mysecret", id="myid"', "myid", "mysecret"),
            # Double quotes - secret only
            ('ApiKey   secret="mysecret"', None, "mysecret"),
            # Single quotes - id first
            ("ApiKey   id='myid', secret='mysecret'", "myid", "mysecret"),
            # Single quotes - secret first
            ("ApiKey   secret='mysecret', id='myid'", "myid", "mysecret"),
            # Single quotes - secret only
            ("ApiKey   secret='mysecret'", None, "mysecret"),
            # No quotes - id first
            ("ApiKey   id=myid, secret=mysecret", "myid", "mysecret"),
            # No quotes - secret first
            ("ApiKey   secret=mysecret, id=myid", "myid", "mysecret"),
            # No quotes - secret only
            ("ApiKey   secret=mysecret", None, "mysecret"),
            # Mixed quotes - single id, double secret
            ("ApiKey   id='myid', secret=\"mysecret\"", "myid", "mysecret"),
            # Extra spaces
            ("ApiKey     id = 'myid' ,  secret = 'mysecret'  ", "myid", "mysecret"),
            # Empty id (treated as None)
            ('ApiKey   id="", secret="mysecret"', None, "mysecret"),
            # Comma in quoted value
            ('ApiKey   secret="my,secret"', None, "my,secret"),
        ],
    )
    def test_parse_various_formats(
        self,
        header: str,
        expected_id: str | None,
        expected_secret: str | None,
    ):
        """Test parsing various valid header formats."""
        auth_id, auth_secret = parse_upstream_auth(header)
        assert auth_id == expected_id
        assert auth_secret == expected_secret

    @pytest.mark.parametrize(
        ("header", "expected_id", "expected_secret"),
        [
            # Standard format
            ('ApiKey id="abc", secret="def"', "abc", "def"),
            # Extra spaces around equals and comma
            ('ApiKey   id   =   "abc"   ,    secret   =    "def"', "abc", "def"),
            # Single quotes with leading space in value
            ("ApiKey   id   =   ' abc' ,  secret    =    'def'", "abc", "def"),
            # Secret only
            ("ApiKey secret='only-secret'", None, "only-secret"),
            # Secret first, then id
            ('ApiKey secret="sec", id="myid"', "myid", "sec"),
            # Leading space in quoted secret
            ('ApiKey   secret   =   " sec"', None, "sec"),
            # Leading space in quoted id (id only - should fail as secret is required)
            ('ApiKey   id   =   " myid"', None, None),
            # Escaped quotes in values - single quotes containing double quotes
            ("ApiKey secret='se\"c', id='m\"yid'", 'm"yid', 'se"c'),
            # Escaped quotes in values - double quotes containing single quotes
            ('ApiKey secret="se\'c", id="m\'yid"', "m'yid", "se'c"),
            # Mixed quotes - double id, unquoted secret
            ('ApiKey   id   =   "abc"   ,    secret   =    def', "abc", "def"),
            # No quotes for both
            ("ApiKey   id   =   abc   ,    secret   =    def", "abc", "def"),
            # Unquoted id only (should fail as secret is required)
            ("ApiKey   id   =    myid", None, None),
        ],
    )
    def test_parse_edge_cases(
        self,
        header: str,
        expected_id: str | None,
        expected_secret: str | None,
    ):
        """Test parsing edge cases and special scenarios."""
        auth_id, auth_secret = parse_upstream_auth(header)
        assert auth_id == expected_id
        assert auth_secret == expected_secret
