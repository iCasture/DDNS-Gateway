"""Tests for server authentication, method validation, and error handling."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette import status as st_status

from ddns_gateway.config import (
    AuthConfig,
    Config,
    HealthConfig,
)
from ddns_gateway.server import create_app, parse_upstream_auth


class TestAuthMiddleware:
    """Tests for authentication middleware using Authorization header."""

    def test_missing_token_returns_401(self, client_auth_enabled):
        """Test that missing Authorization header returns 401."""
        response = client_auth_enabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
        )

        assert response.status_code == st_status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert data["status"] == "error"
        assert any(e["code"] == "MISSING_AUTH_TOKEN" for e in data["errors"])

    def test_invalid_token_returns_403(self, client_auth_enabled):
        """Test that invalid Bearer token returns 403."""
        response = client_auth_enabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
            headers={"Authorization": "Bearer invalid-token"},
        )

        assert response.status_code == st_status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["status"] == "error"
        assert any(e["code"] == "INVALID_AUTH_TOKEN" for e in data["errors"])

    def test_valid_token_passes_auth(self, client_auth_enabled):
        """Test that valid Bearer token passes authentication (may fail at provider)."""
        response = client_auth_enabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
            headers={"Authorization": "Bearer valid-token"},
        )

        # Should not be 401/403 - may be 400 due to missing provider credentials
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]

    def test_auth_disabled_allows_request(self, client_auth_disabled):
        """Test that auth disabled allows request without Authorization header."""
        response = client_auth_disabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
        )

        # Should not be 401/403
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]

    def test_bearer_token_case_insensitive(self, client_auth_enabled):
        """Test that 'bearer' prefix is case-insensitive."""
        response = client_auth_enabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
            headers={"Authorization": "BEARER valid-token"},
        )

        # Should not be 401/403
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]


class TestValidationErrorHandler:
    """Tests for validation error handling."""

    def test_missing_value_returns_400(self, client_auth_disabled):
        """Test that missing value parameter returns 400."""
        # PUT without value in body or query
        response = client_auth_disabled.put("/v1/ddns/cloudflare/example.com/A/home")

        assert response.status_code == st_status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["status"] == "error"
        assert any("value" in e.get("field", "") for e in data["errors"])

    def test_invalid_provider_returns_400(self, client_auth_disabled):
        """Test that invalid provider returns 400."""
        response = client_auth_disabled.put(
            "/v1/ddns/invalid_provider/example.com/A/home",
            json={"value": "1.2.3.4"},
        )

        assert response.status_code == st_status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["status"] == "error"
        assert any(e["code"] == "INVALID_PROVIDER" for e in data["errors"])

    def test_missing_body_params_returns_422(self, client_auth_disabled):
        """Test that missing parameters returns 422 with clear message."""
        # Send empty body - but body is optional, so it falls back to query.
        # To trigger 422, we need to send a body that is invalid (e.g. strict type check)
        # OR force body parsing.
        # But UpsertRequest fields are defaults or None... wait.
        # UpsertRequest: value is required.
        # If we send json={}, value is missing.
        response = client_auth_disabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={},  # Empty body, should fail Pydantic validation for 'value'
        )

        assert response.status_code == st_status.HTTP_422_UNPROCESSABLE_CONTENT
        data = response.json()
        assert data["status"] == "error"
        assert len(data["errors"]) == 1
        assert data["errors"][0]["code"] == "VALIDATION_ERROR"
        assert "Missing required fields: value" in data["errors"][0]["message"]

    def test_partial_body_params_correctly_lists_missing(self, client_auth_disabled):
        """Test that partial parameters correctly lists only missing ones."""
        # 'value' is the only required field in UpsertRequest.
        # So missing it is the main case.
        # Let's try to trigger multiple missing fields if possible.
        # But only 'value' is required in UpsertRequest definition above.
        # Let's check UpsertRequest definition in models.py.
        # It has value: str = Field(..., min_length=1)
        # All others are optional.
        # So we can't easily trigger multiple missing fields with the current model.
        # However, the user asked for "lists only missing ones".
        # If I had more required fields, this would be relevant.
        # I'll stick to testing the message format.
        response = client_auth_disabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={},
        )
        assert response.status_code == st_status.HTTP_422_UNPROCESSABLE_CONTENT
        data = response.json()
        msg = data["errors"][0]["message"]
        assert "Missing required fields: value" in msg
        assert "ttl" not in msg  # Optional
        assert "comment" not in msg  # Optional


class TestDeleteEndpoint:
    """Tests for DELETE /v1/ddns/{provider}/{zone}/{type}/{record} endpoint."""

    def test_delete_with_auth(self, client_auth_enabled):
        """Test DELETE endpoint with valid auth."""
        response = client_auth_enabled.delete(
            "/v1/ddns/cloudflare/example.com/A/home",
            headers={"Authorization": "Bearer valid-token"},
        )

        # Should not be 401/403
        assert response.status_code not in [
            st_status.HTTP_401_UNAUTHORIZED,
            st_status.HTTP_403_FORBIDDEN,
        ]

    def test_delete_without_auth_returns_401(self, client_auth_enabled):
        """Test DELETE endpoint without auth returns 401."""
        response = client_auth_enabled.delete("/v1/ddns/cloudflare/example.com/A/home")

        assert response.status_code == st_status.HTTP_401_UNAUTHORIZED


class TestHealthEndpoint:
    """Tests for health check endpoint.

    The /health route is dynamically registered based on config during
    lifespan startup. Each test creates a fresh FastAPI app instance
    with the appropriate configuration.
    """

    def test_health_bypasses_auth(self):
        """Test that health endpoint bypasses authentication."""
        # Create config with health enabled and auth enabled
        config = Config()
        config.health = HealthConfig(enabled=True)
        config.auth = AuthConfig(enabled=True, tokens=["valid-token"])

        # Create a fresh app with this config
        app = create_app(config)

        # Use context manager to ensure lifespan events are triggered
        with TestClient(app) as test_client:
            # Health endpoint should be accessible without authentication
            response = test_client.get("/health")

            assert response.status_code == st_status.HTTP_200_OK
            assert response.json() == {"status": "ok"}

    def test_health_disabled_returns_404(self):
        """Test that disabled health endpoint returns 404."""
        # Create config with health disabled
        config = Config()
        config.health = HealthConfig(enabled=False)
        config.auth = AuthConfig(enabled=False, tokens=[])

        # Create a fresh app with this config
        app = create_app(config)

        # Use context manager to ensure lifespan events are triggered
        with TestClient(app) as test_client:
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


class TestDebugInfo:
    """Tests for debug information in responses."""

    def test_debug_info_included_when_enabled(self, client_debug_enabled):
        """Test that debug info is included when enabled."""
        response = client_debug_enabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
        )

        data = response.json()
        # Response should include debug field (may fail at provider level,
        # but debug info should still be present)
        assert "debug" in data
        assert data["debug"] is not None
        assert "raw_input" in data["debug"]
        assert data["debug"]["raw_input"]["zone"] == "example.com"
        assert data["debug"]["raw_input"]["record"] == "home"
        assert data["debug"]["raw_input"]["type"] == "A"
        assert data["debug"]["raw_input"]["value"] == "1.2.3.4"

    def test_debug_info_not_included_when_disabled(self, client_auth_disabled):
        """Test that debug info is not included when disabled."""
        response = client_auth_disabled.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
        )

        data = response.json()
        # Response should not include debug field
        assert "debug" not in data

    def test_debug_info_shows_normalization(self, client_debug_enabled):
        """Test that debug info shows normalized values."""
        response = client_debug_enabled.put(
            "/v1/ddns/cloudflare/EXAMPLE.COM/a/HOME",  # Mixed case
            json={"value": "  1.2.3.4  "},  # With whitespace
        )

        data = response.json()
        assert "debug" in data
        assert data["debug"] is not None

        # Raw input should preserve original values
        raw = data["debug"]["raw_input"]
        assert raw["zone"] == "EXAMPLE.COM"
        assert raw["record"] == "HOME"
        assert raw["type"] == "a"
        assert raw["value"] == "  1.2.3.4  "

        # Normalized should show cleaned values
        if data["debug"]["normalized"] is not None:
            norm = data["debug"]["normalized"]
            assert norm["zone"] == "example.com"  # Lowercased
            assert norm["record"] == "home"  # Lowercased
            assert norm["type"] == "A"  # Uppercased
            assert norm["value"] == "1.2.3.4"  # Stripped

    def test_debug_info_on_validation_error(self, client_debug_enabled):
        """Test that debug info is included even on validation errors."""
        response = client_debug_enabled.put(
            "/v1/ddns/cloudflare/example.com/INVALID/home",  # Invalid record type
            json={"value": "1.2.3.4"},
        )

        data = response.json()
        assert data["status"] == "error"
        assert "debug" in data
        assert data["debug"] is not None
        assert "raw_input" in data["debug"]
        # Normalized may be None for validation errors
