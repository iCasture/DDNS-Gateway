"""Tests for provider base class and concrete providers."""

from __future__ import annotations

import pytest

from ddns_gateway.providers.aliyun import AliyunProvider
from ddns_gateway.providers.base import BaseDNSProvider, ProviderError
from ddns_gateway.providers.cloudflare import CloudFlareProvider
from ddns_gateway.providers.tencent import TencentProvider

# =============================================================================
# ProviderError Tests
# =============================================================================


class TestProviderError:
    """Tests for ProviderError exception."""

    def test_basic_error(self):
        """Test creating a basic ProviderError."""
        error = ProviderError("Zone not found")
        assert str(error) == "Zone not found"
        assert error.message == "Zone not found"
        assert error.code is None

    def test_error_with_code(self):
        """Test creating a ProviderError with error code."""
        error = ProviderError("API rate limited", code="RATE_LIMITED")
        assert str(error) == "API rate limited"
        assert error.message == "API rate limited"
        assert error.code == "RATE_LIMITED"

    def test_error_is_exception(self):
        """Test that ProviderError is a proper exception."""
        with pytest.raises(ProviderError) as exc_info:
            raise ProviderError("Test error")  # noqa: TRY003, EM101
        assert str(exc_info.value) == "Test error"


# =============================================================================
# BaseDNSProvider Tests
# =============================================================================


class TestBaseDNSProvider:
    """Tests for BaseDNSProvider class."""

    def _create_test_provider(self) -> BaseDNSProvider:
        """Create a concrete implementation for testing."""

        class TestProvider(BaseDNSProvider):
            @property
            def name(self):
                return "test"

            async def find_record(self, *args, **kwargs):
                pass

            async def create_record(self, *args, **kwargs):
                pass

            async def update_record(self, *args, **kwargs):
                pass

            async def delete_record(self, *args, **kwargs):
                pass

        return TestProvider()

    def test_build_fqdn_with_subdomain(self):
        """Test build_fqdn with subdomain records."""
        provider = self._create_test_provider()
        assert provider.build_fqdn("example.com", "home") == "home.example.com"
        assert provider.build_fqdn("example.com", "www") == "www.example.com"

    def test_build_fqdn_with_root(self):
        """Test build_fqdn with root record (@)."""
        provider = self._create_test_provider()
        assert provider.build_fqdn("example.com", "@") == "example.com"
        assert provider.build_fqdn("example.com", "") == "example.com"

    def test_build_fqdn_with_nested_subdomain(self):
        """Test build_fqdn with nested subdomain."""
        provider = self._create_test_provider()
        assert provider.build_fqdn("example.com", "deep.sub") == "deep.sub.example.com"


# =============================================================================
# CloudFlareProvider Tests
# =============================================================================


class TestCloudFlareProvider:
    """Tests for CloudFlareProvider class."""

    def test_provider_name(self):
        """Test that provider name is correct."""
        provider = CloudFlareProvider()
        assert provider.name == "cloudflare"

    def test_build_fqdn(self):
        """Test build_fqdn for CloudFlare provider."""
        provider = CloudFlareProvider()
        assert provider.build_fqdn("example.com", "www") == "www.example.com"
        assert provider.build_fqdn("example.com", "@") == "example.com"


# =============================================================================
# AliyunProvider Tests
# =============================================================================


class TestAliyunProvider:
    """Tests for AliyunProvider class."""

    def test_provider_name(self):
        """Test that provider name is correct."""
        provider = AliyunProvider()
        assert provider.name == "aliyun"

    def test_build_fqdn(self):
        """Test build_fqdn for Aliyun provider."""
        provider = AliyunProvider()
        assert provider.build_fqdn("example.com", "home") == "home.example.com"
        assert provider.build_fqdn("example.com", "@") == "example.com"


# =============================================================================
# TencentProvider Tests
# =============================================================================


class TestTencentProvider:
    """Tests for TencentProvider class."""

    def test_provider_name(self):
        """Test that provider name is correct."""
        provider = TencentProvider()
        assert provider.name == "tencent"

    def test_build_fqdn(self):
        """Test build_fqdn for Tencent provider."""
        provider = TencentProvider()
        assert provider.build_fqdn("example.com", "api") == "api.example.com"
        assert provider.build_fqdn("example.com", "@") == "example.com"
