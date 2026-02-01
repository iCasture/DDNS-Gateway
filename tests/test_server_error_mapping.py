"""Tests for HTTP status code mapping and error response handling."""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from starlette import status as st_status

from ddns_gateway.config import (
    AuthConfig,
    Config,
    DedupeConfig,
    HealthConfig,
)
from ddns_gateway.models import (
    DDNSResponse,
    ErrorCode,
    ErrorModel,
    RecordInfo,
)
from ddns_gateway.server import create_app


class TestErrorResponses:
    """Tests for HTTP status code mapping of error codes."""

    @pytest.fixture
    def app_for_error_test(self):
        """Create a test app with auth disabled."""
        config = Config()
        config.auth = AuthConfig(enabled=False, tokens=[])
        config.health = HealthConfig(enabled=True)
        return create_app(config)

    @pytest.fixture
    def client_for_error_test(self, app_for_error_test):
        """Create a test client with auth disabled."""
        with TestClient(app_for_error_test) as client:
            yield client

    @pytest.mark.parametrize(
        ("error_code", "expected_status"),
        [
            (ErrorCode.VALIDATION_ERROR, st_status.HTTP_400_BAD_REQUEST),
            (ErrorCode.MISSING_GATEWAY_TOKEN, st_status.HTTP_401_UNAUTHORIZED),
            (ErrorCode.INVALID_GATEWAY_TOKEN, st_status.HTTP_401_UNAUTHORIZED),
            (ErrorCode.ZONE_NOT_FOUND, st_status.HTTP_404_NOT_FOUND),
            (ErrorCode.MULTIPLE_RECORDS_FOUND, st_status.HTTP_409_CONFLICT),
            (ErrorCode.INTERNAL_ERROR, st_status.HTTP_500_INTERNAL_SERVER_ERROR),
            (ErrorCode.UPSTREAM_API_ERROR, st_status.HTTP_502_BAD_GATEWAY),
            (ErrorCode.SINGLEFLIGHT_LEADER_FAILED, st_status.HTTP_502_BAD_GATEWAY),
            (ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT, st_status.HTTP_504_GATEWAY_TIMEOUT),
            ("UNKNOWN_ERROR", st_status.HTTP_400_BAD_REQUEST),  # Default case
        ],
    )
    def test_error_code_mapping(
        self,
        client_for_error_test,
        monkeypatch,
        error_code,
        expected_status,
    ):
        """Test that ErrorCode maps to correct HTTP status code."""
        # Mock service to return specific error
        mock_service = AsyncMock()
        mock_response = DDNSResponse(
            status="error",
            action=None,
            upstream_called=False,
            provider="test",
            record=RecordInfo(zone="example.com", type="A", name="home"),
            errors=[ErrorModel(code=error_code, message="Test error")],
        )
        mock_service.return_value = mock_response

        monkeypatch.setattr(
            "ddns_gateway.server.upsert_record_service",
            mock_service,
        )

        response = client_for_error_test.put(
            "/v1/ddns/cloudflare/example.com/A/home",
            json={"value": "1.2.3.4"},
        )

        assert response.status_code == expected_status


class TestSingleflightHeaders:
    """Tests for Singleflight related headers."""

    def test_retry_after_header_present(self, monkeypatch):
        """Test that Retry-After header is present on 504 Singleflight timeout."""
        # 1. Setup config with specific lease_sec
        config = Config()
        config.auth = AuthConfig(enabled=False, tokens=[])
        config.health = HealthConfig(enabled=True)
        config.dedupe = DedupeConfig(enabled=True, singleflight_lease_sec=60.0)

        # Create app with this config
        app = create_app(config)

        # 2. Setup mock service to return SINGLEFLIGHT_WAIT_TIMEOUT
        mock_service = AsyncMock()
        mock_response = DDNSResponse(
            status="error",
            action=None,
            upstream_called=False,
            provider="test",
            record=RecordInfo(zone="example.com", type="A", name="home"),
            errors=[
                ErrorModel(
                    code=ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT,
                    message="Timeout",
                ),
            ],
        )
        mock_service.return_value = mock_response
        monkeypatch.setattr(
            "ddns_gateway.server.upsert_record_service",
            mock_service,
        )

        # 3. Make request
        with TestClient(app) as client:
            response = client.put(
                "/v1/ddns/cloudflare/example.com/A/home",
                json={"value": "1.2.3.4"},
            )

            # 4. Assertions
            assert response.status_code == st_status.HTTP_504_GATEWAY_TIMEOUT
            assert "Retry-After" in response.headers
            assert response.headers["Retry-After"] == "60"

    def test_retry_after_header_ceil_value(self, monkeypatch):
        """Test that Retry-After header value is rounded up."""
        # 1. Setup config with float lease_sec
        config = Config()
        config.auth = AuthConfig(enabled=False, tokens=[])
        config.dedupe = DedupeConfig(enabled=True, singleflight_lease_sec=10.1)

        # Create app with this config
        app = create_app(config)

        # 2. Setup mock service
        mock_service = AsyncMock()
        mock_response = DDNSResponse(
            status="error",
            action=None,
            upstream_called=False,
            provider="test",
            record=RecordInfo(zone="example.com", type="A", name="home"),
            errors=[
                ErrorModel(
                    code=ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT,
                    message="Timeout",
                ),
            ],
        )
        mock_service.return_value = mock_response
        monkeypatch.setattr(
            "ddns_gateway.server.upsert_record_service",
            mock_service,
        )

        # 3. Make request
        with TestClient(app) as client:
            response = client.put(
                "/v1/ddns/cloudflare/example.com/A/home",
                json={"value": "1.2.3.4"},
            )

            # 4. Assertions
            assert response.status_code == st_status.HTTP_504_GATEWAY_TIMEOUT
            assert response.headers["Retry-After"] == "11"  # ceil(10.1) == 11
