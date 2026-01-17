"""Tests for service layer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ddns_gateway.models import ErrorCode, WarningCode, WarningModel
from ddns_gateway.providers.base import BaseDNSProvider, ProviderError
from ddns_gateway.service import delete_record_service, upsert_record_service
from ddns_gateway.types import ExistingRecord, UpstreamResult

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_provider() -> MagicMock:
    """Create a mock provider instance."""
    provider = MagicMock(spec=BaseDNSProvider)
    provider.name = "test"
    return provider


@pytest.fixture
def mock_credentials() -> dict[str, str]:
    """Create mock credentials."""
    return {"id": "test_id", "secret": "test_secret"}


# =============================================================================
# Upsert Service Tests
# =============================================================================


class TestUpsertService:
    """Tests for upsert_record_service function."""

    @pytest.mark.asyncio
    async def test_create_new_record(self, mock_provider, mock_credentials):
        """Test creating a new record when none exists."""
        # Setup: find_record returns None (no existing record)
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert response.action == "created"
        assert response.upstream_called is True
        mock_provider.find_record.assert_called_once()
        mock_provider.create_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_existing_record(self, mock_provider, mock_credentials):
        """Test updating an existing record with different value."""
        existing = ExistingRecord(
            record_id="rec_123",
            zone_id="zone_456",
            value="1.1.1.1",  # Old value
            ttl=300,
            comment=None,
            proxied=False,
            raw={"type": "A", "name": "home.example.com"},
        )
        mock_provider.find_record = AsyncMock(return_value=existing)
        mock_provider.update_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="updated",
                message="Record updated",
                record_id="rec_123",
                previous_value="1.1.1.1",
            ),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="2.2.2.2",  # New value
            ttl=300,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert response.action == "updated"
        assert response.upstream_called is True
        mock_provider.update_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_change_when_values_match(self, mock_provider, mock_credentials):
        """Test that no update is made when values already match."""
        existing = ExistingRecord(
            record_id="rec_123",
            zone_id="zone_456",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=False,
            raw={"type": "A", "name": "home.example.com"},
        )
        mock_provider.find_record = AsyncMock(return_value=existing)

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",  # Same value
            ttl=None,  # No TTL specified
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert response.action == "unchanged"
        assert response.upstream_called is False
        mock_provider.update_record.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_zone_returns_error(self, mock_provider, mock_credentials):
        """Test that invalid zone returns validation error."""
        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="",  # Empty zone
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "error"
        assert len(response.errors) > 0

    @pytest.mark.asyncio
    async def test_invalid_record_type_returns_error(
        self,
        mock_provider,
        mock_credentials,
    ):
        """Test that invalid record type returns error."""
        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="INVALID",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "error"
        assert response.errors[0].code == ErrorCode.INVALID_RECORD_TYPE

    @pytest.mark.asyncio
    async def test_provider_find_error(self, mock_provider, mock_credentials):
        """Test handling of provider find_record error."""
        mock_provider.find_record = AsyncMock(
            side_effect=ProviderError("Zone not found"),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "error"
        assert response.errors[0].code == ErrorCode.UPSTREAM_API_ERROR

    @pytest.mark.asyncio
    async def test_provider_create_failure(self, mock_provider, mock_credentials):
        """Test handling of provider create_record failure."""
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=False,
                action="created",
                message="API error: rate limited",
            ),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
        )

        assert response.status == "error"
        assert "rate limited" in response.errors[0].message

    @pytest.mark.asyncio
    async def test_warnings_propagated_from_provider(
        self,
        mock_provider,
        mock_credentials,
    ):
        """Test that warnings from provider are propagated to response."""
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
                warnings=[
                    WarningModel(
                        code=WarningCode.CF_PROXIED_IGNORED_FOR_TXT,
                        message="Proxied ignored for TXT",
                    ),
                ],
            ),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="TXT",
            record="home",
            value="v=spf1 -all",
            ttl=None,
            comment=None,
            proxied=True,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert len(response.warnings) == 1
        assert response.warnings[0].code == WarningCode.CF_PROXIED_IGNORED_FOR_TXT


# =============================================================================
# Delete Service Tests
# =============================================================================


class TestDeleteService:
    """Tests for delete_record_service function."""

    @pytest.mark.asyncio
    async def test_delete_existing_record(self, mock_provider, mock_credentials):
        """Test deleting an existing record."""
        existing = ExistingRecord(
            record_id="rec_123",
            zone_id="zone_456",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=False,
            raw={"type": "A", "name": "home.example.com"},
        )
        mock_provider.find_record = AsyncMock(return_value=existing)
        mock_provider.delete_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="deleted",
                message="Record deleted",
                record_id="rec_123",
            ),
        )

        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert response.action == "deleted"
        assert response.upstream_called is True
        mock_provider.delete_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_nonexistent_record(self, mock_provider, mock_credentials):
        """Test deleting a record that doesn't exist returns unchanged."""
        mock_provider.find_record = AsyncMock(return_value=None)

        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert response.action == "unchanged"
        assert response.upstream_called is False
        mock_provider.delete_record.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_provider_error(self, mock_provider, mock_credentials):
        """Test handling of provider delete_record error."""
        existing = ExistingRecord(
            record_id="rec_123",
            zone_id="zone_456",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=False,
            raw={},
        )
        mock_provider.find_record = AsyncMock(return_value=existing)
        mock_provider.delete_record = AsyncMock(side_effect=Exception("Network error"))

        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            credentials=mock_credentials,
        )

        assert response.status == "error"
        assert "Network error" in response.errors[0].message

    @pytest.mark.asyncio
    async def test_delete_invalid_zone(self, mock_provider, mock_credentials):
        """Test that invalid zone returns validation error."""
        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="",  # Empty zone
            record_type="A",
            record="home",
            credentials=mock_credentials,
        )

        assert response.status == "error"

    @pytest.mark.asyncio
    async def test_delete_invalid_record_type(self, mock_provider, mock_credentials):
        """Test that invalid record type returns error."""
        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="INVALID",
            record="home",
            credentials=mock_credentials,
        )

        assert response.status == "error"
        assert response.errors[0].code == ErrorCode.INVALID_RECORD_TYPE


# =============================================================================
# Debug Info Tests
# =============================================================================


class TestDebugInfo:
    """Tests for debug information in service responses."""

    @pytest.mark.asyncio
    async def test_upsert_debug_info_enabled(self, mock_provider, mock_credentials):
        """Test that debug info is included when enabled for upsert."""
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="EXAMPLE.COM",  # Mixed case
            record_type="a",  # Lowercase
            record="HOME",  # Uppercase
            value="  1.2.3.4  ",  # With whitespace
            ttl=300,
            comment="  test comment  ",  # With whitespace
            proxied=True,
            credentials=mock_credentials,
            include_debug_info=True,
        )

        assert response.status == "success"
        assert response.debug is not None

        # Check raw input
        assert response.debug.raw_input is not None
        assert response.debug.raw_input["zone"] == "EXAMPLE.COM"
        assert response.debug.raw_input["record"] == "HOME"
        assert response.debug.raw_input["type"] == "a"
        assert response.debug.raw_input["value"] == "  1.2.3.4  "
        assert response.debug.raw_input["ttl"] == 300
        assert response.debug.raw_input["comment"] == "  test comment  "
        assert response.debug.raw_input["proxied"] is True

        # Check normalized
        assert response.debug.normalized is not None
        assert response.debug.normalized["zone"] == "example.com"
        assert response.debug.normalized["record"] == "home"
        assert response.debug.normalized["type"] == "A"
        assert response.debug.normalized["value"] == "1.2.3.4"
        assert response.debug.normalized["ttl"] == 300
        assert response.debug.normalized["comment"] == "test comment"
        assert response.debug.normalized["proxied"] is True

    @pytest.mark.asyncio
    async def test_upsert_debug_info_disabled(self, mock_provider, mock_credentials):
        """Test that debug info is not included when disabled for upsert."""
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
            include_debug_info=False,  # Disabled
        )

        assert response.status == "success"
        assert response.debug is None

    @pytest.mark.asyncio
    async def test_upsert_debug_info_on_error(self, mock_provider, mock_credentials):
        """Test that debug info is included on validation error."""
        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="INVALID",  # Invalid type
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            credentials=mock_credentials,
            include_debug_info=True,
        )

        assert response.status == "error"
        assert response.debug is not None
        assert response.debug.raw_input is not None
        # Normalized may be None for validation errors
        assert response.debug.raw_input["type"] == "INVALID"

    @pytest.mark.asyncio
    async def test_delete_debug_info_enabled(self, mock_provider, mock_credentials):
        """Test that debug info is included when enabled for delete."""
        mock_provider.find_record = AsyncMock(return_value=None)

        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="EXAMPLE.COM",  # Mixed case
            record_type="a",  # Lowercase
            record="HOME",  # Uppercase
            credentials=mock_credentials,
            include_debug_info=True,
        )

        assert response.status == "success"
        assert response.debug is not None

        # Check raw input
        assert response.debug.raw_input is not None
        assert response.debug.raw_input["zone"] == "EXAMPLE.COM"
        assert response.debug.raw_input["record"] == "HOME"
        assert response.debug.raw_input["type"] == "a"

        # Check normalized
        assert response.debug.normalized is not None
        assert response.debug.normalized["zone"] == "example.com"
        assert response.debug.normalized["record"] == "home"
        assert response.debug.normalized["type"] == "A"

    @pytest.mark.asyncio
    async def test_delete_debug_info_disabled(self, mock_provider, mock_credentials):
        """Test that debug info is not included when disabled for delete."""
        mock_provider.find_record = AsyncMock(return_value=None)

        response = await delete_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            credentials=mock_credentials,
            include_debug_info=False,  # Disabled
        )

        assert response.status == "success"
        assert response.debug is None
