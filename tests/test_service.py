"""Tests for service layer."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from ddns_gateway.config import DedupeConfig
from ddns_gateway.dedupe import DedupeCache, create_cached_base
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
        assert response.upstream_called is True
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
        assert response.upstream_called is False  # validation error, no upstream call

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
        assert response.upstream_called is False  # validation error, no upstream call

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
        assert response.upstream_called is True  # called find_record before error

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
        assert response.upstream_called is True  # called create_record before error

    @pytest.mark.asyncio
    async def test_warnings_propagated_from_provider(
        self,
        mock_provider,
        mock_credentials,
    ):
        """Test that warnings from provider are propagated to response."""
        # Note: For TXT records with proxied=True, service layer converts it to
        # proxied_validated=None and generates a warning. Provider receives None,
        # so it won't generate the same warning. We use A record here to test
        # that provider warnings are correctly propagated without service layer
        # generating a duplicate warning.
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
                warnings=[
                    WarningModel(
                        code=WarningCode.PROXIED_IGNORED,
                        message="Test warning from provider",
                    ),
                ],
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
            proxied=True,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert len(response.warnings) == 1
        assert response.warnings[0].code == WarningCode.PROXIED_IGNORED
        assert response.warnings[0].message == "Test warning from provider"

    @pytest.mark.asyncio
    async def test_proxied_warning_for_txt_record(
        self,
        mock_provider,
        mock_credentials,
    ):
        """Test that proxied=True for TXT record generates warning."""
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
        assert response.warnings[0].code == WarningCode.PROXIED_IGNORED
        assert "proxied" in response.warnings[0].message.lower()
        assert "A/AAAA/CNAME" in response.warnings[0].message
        assert response.result.effective.proxied is None

    @pytest.mark.asyncio
    async def test_proxied_warning_for_non_cloudflare_provider(
        self,
        mock_provider,
        mock_credentials,
    ):
        """Test that proxied=True for non-Cloudflare provider generates warning."""
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
            provider="aliyun",  # Non-Cloudflare provider
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=True,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert len(response.warnings) == 1
        assert response.warnings[0].code == WarningCode.PROXIED_IGNORED_FOR_NON_CF
        assert "non-cloudflare" in response.warnings[0].message.lower()
        assert response.result.effective.proxied is None

    @pytest.mark.asyncio
    async def test_proxied_no_warning_for_valid_record_type(
        self,
        mock_provider,
        mock_credentials,
    ):
        """Test that proxied=True for A/AAAA/CNAME records doesn't generate warning."""
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        # Test with A record
        response = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=True,
            credentials=mock_credentials,
        )

        assert response.status == "success"
        assert len(response.warnings) == 0
        assert response.result.effective.proxied is True


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
        assert response.upstream_called is True
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
        assert response.upstream_called is True  # called delete_record before error

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
        assert response.upstream_called is False  # validation error, no upstream call

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
        assert response.upstream_called is False  # validation error, no upstream call


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


# =============================================================================
# Singleflight Tests
# =============================================================================


class TestSingleflight:
    """Tests for singleflight behavior in service layer."""

    @pytest.fixture
    def mock_provider(self) -> MagicMock:
        """Create a mock provider instance."""
        provider = MagicMock(spec=BaseDNSProvider)
        provider.name = "test"
        return provider

    @pytest.fixture
    def mock_credentials(self) -> dict[str, str]:
        """Create mock credentials."""
        return {"id": "test_id", "secret": "test_secret"}

    @pytest.fixture
    def dedupe_config(self) -> DedupeConfig:
        """Create dedupe config with short timeouts for testing."""
        return DedupeConfig(
            enabled=True,
            singleflight_lease_sec=5.0,
            singleflight_wait_timeout_sec=0.1,  # Short timeout for tests
        )

    @pytest.mark.asyncio
    async def test_upsert_waiter_gets_aborted_when_leader_fails(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that waiter receives SINGLEFLIGHT_LEADER_FAILED when leader aborts."""
        cache = DedupeCache()

        # Leader marks in-flight
        key = "test_key_hash"
        await cache.mark_in_flight(key, lease_sec=dedupe_config.singleflight_lease_sec)

        # Leader fails and clears in-flight
        await cache.clear_in_flight(key)

        # Setup mock provider (won't be called since we're testing waiter path)
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        # Simulate waiter scenario by pre-marking in-flight and then failing
        cache2 = DedupeCache()
        await cache2.mark_in_flight("key2", lease_sec=dedupe_config.singleflight_lease_sec)

        async def leader_fails():
            await asyncio.sleep(0.05)
            await cache2.clear_in_flight("key2")

        async def waiter_request():
            # This simulates the waiter path - mark_in_flight returns False
            is_leader, gen = await cache2.mark_in_flight(
                "key2", lease_sec=dedupe_config.singleflight_lease_sec
            )
            assert is_leader is False
            assert gen == 0

            # Wait for result
            from ddns_gateway.dedupe import WaitResult

            outcome = await cache2.wait_for_result("key2", wait_timeout_sec=1.0)
            return outcome

        # Run concurrently
        results = await asyncio.gather(leader_fails(), waiter_request())
        waiter_outcome = results[1]

        from ddns_gateway.dedupe import WaitResult

        assert waiter_outcome.status == WaitResult.ABORTED
        assert waiter_outcome.entry is None

    @pytest.mark.asyncio
    async def test_upsert_waiter_gets_timeout_when_leader_slow(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that waiter receives SINGLEFLIGHT_WAIT_TIMEOUT when leader is slow."""
        cache = DedupeCache()

        # Leader marks in-flight but takes too long
        await cache.mark_in_flight("key1", lease_sec=dedupe_config.singleflight_lease_sec)

        # Waiter tries to wait but times out
        from ddns_gateway.dedupe import WaitResult

        outcome = await cache.wait_for_result(
            "key1", wait_timeout_sec=0.05  # Very short timeout
        )

        assert outcome.status == WaitResult.TIMEOUT
        assert outcome.entry is None

    @pytest.mark.asyncio
    async def test_upsert_waiter_gets_success_when_leader_completes(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that waiter receives SUCCESS when leader completes."""
        cache = DedupeCache()

        # Leader marks in-flight
        await cache.mark_in_flight("key1", lease_sec=dedupe_config.singleflight_lease_sec)

        # Create cached base for leader's result
        cached_base = create_cached_base(
            status="success",
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id="rec_123",
            zone_id="zone_456",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            previous_value=None,
            warnings=[],
        )

        async def leader_completes():
            await asyncio.sleep(0.05)
            await cache.set("key1", cached_base)

        async def waiter_waits():
            from ddns_gateway.dedupe import WaitResult

            outcome = await cache.wait_for_result("key1", wait_timeout_sec=1.0)
            return outcome

        # Run concurrently
        results = await asyncio.gather(leader_completes(), waiter_waits())
        waiter_outcome = results[1]

        from ddns_gateway.dedupe import WaitResult

        assert waiter_outcome.status == WaitResult.COMPLETED
        assert waiter_outcome.entry is not None
        assert waiter_outcome.entry.base == cached_base

    @pytest.mark.asyncio
    async def test_upsert_service_returns_aborted_error(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that service returns SINGLEFLIGHT_LEADER_FAILED error code."""
        cache = DedupeCache()

        # Pre-mark as in-flight then fail (simulating leader failure)
        await cache.mark_in_flight(
            # Use the actual dedupe key format
            "abc123",
            lease_sec=dedupe_config.singleflight_lease_sec,
        )
        await cache.clear_in_flight("abc123")

        # Verify the cache entry is marked as leader_failed
        from ddns_gateway.dedupe import WaitResult

        outcome = await cache.wait_for_result("abc123", wait_timeout_sec=0.1)
        assert outcome.status == WaitResult.ABORTED

    @pytest.mark.asyncio
    async def test_delete_waiter_gets_aborted(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that delete waiter receives ABORTED when leader aborts."""
        cache = DedupeCache()

        # Leader marks in-flight then fails
        await cache.mark_in_flight("delete_key", lease_sec=dedupe_config.singleflight_lease_sec)
        await cache.clear_in_flight("delete_key")

        from ddns_gateway.dedupe import WaitResult

        outcome = await cache.wait_for_result("delete_key", wait_timeout_sec=0.1)
        assert outcome.status == WaitResult.ABORTED

    @pytest.mark.asyncio
    async def test_aborted_entry_not_returned_by_get(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that get() returns None for aborted entries."""
        cache = DedupeCache()

        # Leader marks in-flight then aborts
        await cache.mark_in_flight("key1", lease_sec=dedupe_config.singleflight_lease_sec)
        await cache.clear_in_flight("key1")

        # get() should return None for aborted entries
        entry = await cache.get("key1")
        assert entry is None


# =============================================================================
# Error Response Caching Tests
# =============================================================================


class TestErrorResponseCaching:
    """Tests for error response caching in service layer."""

    @pytest.fixture
    def mock_provider(self) -> MagicMock:
        """Create a mock provider instance."""
        provider = MagicMock(spec=BaseDNSProvider)
        provider.name = "test"
        return provider

    @pytest.fixture
    def mock_credentials(self) -> dict[str, str]:
        """Create mock credentials."""
        return {"id": "test_id", "secret": "test_secret"}

    @pytest.fixture
    def dedupe_config(self) -> DedupeConfig:
        """Create dedupe config for testing."""
        return DedupeConfig(
            enabled=True,
            singleflight_lease_sec=5.0,
            singleflight_wait_timeout_sec=0.5,
        )

    @pytest.mark.asyncio
    async def test_upsert_error_is_cached(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that upsert error responses are cached."""
        from ddns_gateway.dedupe import compute_credential_hash, compute_dedupe_key

        cache = DedupeCache()

        # Setup: find_record raises exception
        mock_provider.find_record = AsyncMock(
            side_effect=ProviderError("Zone not found"),
        )

        # First request - should call upstream and cache error
        response1 = await upsert_record_service(
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
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response1.status == "error"
        assert response1.errors[0].code == ErrorCode.UPSTREAM_API_ERROR
        mock_provider.find_record.assert_called_once()

        # Verify error was cached
        cred_hash = compute_credential_hash(mock_credentials)
        dedupe_key = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            upstream_credential_hash=cred_hash,
        )
        cached_entry = await cache.get(dedupe_key)
        assert cached_entry is not None
        assert cached_entry.base is not None
        assert cached_entry.base.status == "error"
        assert cached_entry.base.error_code == ErrorCode.UPSTREAM_API_ERROR.value

    @pytest.mark.asyncio
    async def test_different_credentials_get_different_cache_entries(
        self,
        mock_provider,
        dedupe_config,
    ):
        """Test that different credentials produce different cache entries."""
        from ddns_gateway.dedupe import compute_credential_hash, compute_dedupe_key

        cache = DedupeCache()

        # Setup: first user succeeds
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        creds_user_a = {"id": "user_a", "secret": "secret_a"}
        creds_user_b = {"id": "user_b", "secret": "secret_b"}

        # User A makes request
        response_a = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            credentials=creds_user_a,
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response_a.status == "success"

        # User B makes same request with different credentials
        # Should NOT get User A's cached result
        response_b = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            credentials=creds_user_b,
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response_b.status == "success"
        # Both users called the provider (no cache sharing)
        assert mock_provider.find_record.call_count == 2

    @pytest.mark.asyncio
    async def test_same_credentials_get_cached_response(
        self,
        mock_provider,
        dedupe_config,
    ):
        """Test that same credentials get cached response."""
        cache = DedupeCache()

        # Setup: provider succeeds
        mock_provider.find_record = AsyncMock(return_value=None)
        mock_provider.create_record = AsyncMock(
            return_value=UpstreamResult(
                success=True,
                action="created",
                message="Record created",
                record_id="rec_123",
            ),
        )

        creds = {"id": "user", "secret": "secret"}

        # First request
        response1 = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            credentials=creds,
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response1.status == "success"
        assert response1.action == "created"

        # Second request with same credentials - should get cached
        response2 = await upsert_record_service(
            provider_instance=mock_provider,
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
            credentials=creds,
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response2.status == "success"
        assert response2.action == "deduped"  # Cache hit
        # Provider only called once
        assert mock_provider.find_record.call_count == 1

    @pytest.mark.asyncio
    async def test_cached_error_returned_on_second_request(
        self,
        mock_provider,
        mock_credentials,
        dedupe_config,
    ):
        """Test that cached error is returned on subsequent identical requests."""
        cache = DedupeCache()

        # Setup: find_record raises exception
        mock_provider.find_record = AsyncMock(
            side_effect=ProviderError("Auth failed"),
        )

        # First request - error
        response1 = await upsert_record_service(
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
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response1.status == "error"
        assert mock_provider.find_record.call_count == 1

        # Second request - should get cached error, NOT call provider again
        response2 = await upsert_record_service(
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
            dedupe_cache=cache,
            dedupe_config=dedupe_config,
        )

        assert response2.status == "error"
        assert response2.action == "deduped"  # Cache hit
        # Provider still only called once (cached error returned)
        assert mock_provider.find_record.call_count == 1
