"""Tests for provider base class."""

from __future__ import annotations

from ddns_gateway.models import WarningModel
from ddns_gateway.providers.base import BaseDNSProvider, ProviderResult


class TestProviderResult:
    """Tests for ProviderResult class."""

    def test_success_result(self):
        result = ProviderResult(
            success=True,
            message="Record updated",
            action="updated",
            record_id="abc123",
            request_id="req-xyz",
            previous_value="1.1.1.1",
        )
        assert result.success is True
        assert result.message == "Record updated"
        assert result.action == "updated"
        assert result.record_id == "abc123"
        assert result.previous_value == "1.1.1.1"

    def test_error_result(self):
        result = ProviderResult(
            success=False,
            message="Zone not found",
        )
        assert result.success is False
        assert result.message == "Zone not found"
        assert result.action is None

    def test_result_with_warnings(self):
        warning = WarningModel(
            code="comment_partial", message="Failed to update remark",
        )
        result = ProviderResult(
            success=True,
            message="Updated",
            action="updated",
            warnings=[warning],
        )
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "comment_partial"

    def test_to_metadata(self):
        result = ProviderResult(
            success=True,
            message="OK",
            record_id="rec-1",
            request_id="req-1",
            zone_id="zone-1",
            extra={"cf_ray": "ray-id"},
        )
        metadata = result.to_metadata()
        assert metadata.record_id == "rec-1"
        assert metadata.request_id == "req-1"
        assert metadata.zone_id == "zone-1"
        assert metadata.extra == {"cf_ray": "ray-id"}


class TestBaseDNSProvider:
    """Tests for BaseDNSProvider class."""

    def test_build_fqdn_with_subdomain(self):
        # Create a concrete implementation for testing
        class TestProvider(BaseDNSProvider):
            @property
            def name(self):
                return "test"

            async def update_record(self, *args, **kwargs):
                pass

        provider = TestProvider()
        assert provider.build_fqdn("example.com", "home") == "home.example.com"
        assert provider.build_fqdn("example.com", "www") == "www.example.com"

    def test_build_fqdn_with_root(self):
        class TestProvider(BaseDNSProvider):
            @property
            def name(self):
                return "test"

            async def update_record(self, *args, **kwargs):
                pass

        provider = TestProvider()
        assert provider.build_fqdn("example.com", "@") == "example.com"
        assert provider.build_fqdn("example.com", "") == "example.com"
