"""Tests for data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from starlette import status as st_status

from ddns_gateway.models import (
    DNSProvider,
    ProviderMetadata,
    RecordType,
    ResponseData,
    UpdateRequest,
    UpdateResponse,
    WarningModel,
)


class TestDNSProvider:
    """Tests for DNSProvider enum."""

    def test_provider_values(self):
        assert DNSProvider.CLOUDFLARE == "cloudflare"
        assert DNSProvider.ALIYUN == "aliyun"
        assert DNSProvider.TENCENT == "tencent"

    def test_provider_from_string(self):
        assert DNSProvider("cloudflare") == DNSProvider.CLOUDFLARE
        assert DNSProvider("aliyun") == DNSProvider.ALIYUN
        assert DNSProvider("tencent") == DNSProvider.TENCENT


class TestRecordType:
    """Tests for RecordType enum."""

    def test_record_type_values(self):
        assert RecordType.A == "A"
        assert RecordType.AAAA == "AAAA"
        assert RecordType.CNAME == "CNAME"
        assert RecordType.TXT == "TXT"


class TestUpdateRequest:
    """Tests for UpdateRequest model."""

    def test_valid_request(self):
        request = UpdateRequest(
            provider=DNSProvider.CLOUDFLARE,
            zone="example.com",
            record="home",
            record_type=RecordType.A,
            value="1.2.3.4",
        )
        assert request.provider == DNSProvider.CLOUDFLARE
        assert request.zone == "example.com"
        assert request.record == "home"
        assert request.record_type == RecordType.A
        assert request.value == "1.2.3.4"
        assert request.ttl is None
        assert request.comment is None

    def test_request_with_type_alias(self):
        request = UpdateRequest(
            provider=DNSProvider.CLOUDFLARE,
            zone="example.com",
            record="home",
            type=RecordType.AAAA,
            value="2001:db8::1",
        )
        assert request.record_type == RecordType.AAAA

    def test_request_with_all_fields(self):
        request = UpdateRequest(
            provider=DNSProvider.ALIYUN,
            zone="example.com",
            record="@",
            record_type=RecordType.A,
            value="1.2.3.4",
            ttl=300,
            comment="DDNS update",
        )
        assert request.ttl == 300  # noqa: PLR2004
        assert request.comment == "DDNS update"

    def test_invalid_ttl(self):
        with pytest.raises(ValidationError):
            UpdateRequest(
                provider=DNSProvider.CLOUDFLARE,
                zone="example.com",
                record="home",
                record_type=RecordType.A,
                value="1.2.3.4",
                ttl=0,
            )

    def test_empty_zone(self):
        with pytest.raises(ValidationError):
            UpdateRequest(
                provider=DNSProvider.CLOUDFLARE,
                zone="",
                record="home",
                record_type=RecordType.A,
                value="1.2.3.4",
            )

    def test_cname_record(self):
        request = UpdateRequest(
            provider=DNSProvider.CLOUDFLARE,
            zone="example.com",
            record="www",
            record_type=RecordType.CNAME,
            value="example.com",
        )
        assert request.record_type == RecordType.CNAME

    def test_txt_record(self):
        request = UpdateRequest(
            provider=DNSProvider.CLOUDFLARE,
            zone="example.com",
            record="_dmarc",
            record_type=RecordType.TXT,
            value="v=DMARC1; p=none",
        )
        assert request.record_type == RecordType.TXT


class TestUpdateResponse:
    """Tests for UpdateResponse model."""

    def test_success_response(self):
        data = ResponseData(
            provider="cloudflare",
            zone="example.com",
            record="home",
            fqdn="home.example.com",
            type="A",
            value="1.2.3.4",
            ttl=600,
        )
        response = UpdateResponse.success(
            message="Record updated",
            action="updated",
            data=data,
        )
        assert response.status == "success"
        assert response.code == st_status.HTTP_200_OK
        assert response.action == "updated"
        assert response.data is not None
        assert response.data.fqdn == "home.example.com"

    def test_error_response(self):
        response = UpdateResponse.error(
            code=st_status.HTTP_400_BAD_REQUEST,
            message="Invalid provider",
        )
        assert response.status == "error"
        assert response.code == st_status.HTTP_400_BAD_REQUEST
        assert response.message == "Invalid provider"
        assert response.action is None
        assert response.data is None

    def test_response_with_warnings(self):
        warning = WarningModel(code="comment_ignored", message="Comment not supported")
        response = UpdateResponse.error(
            code=st_status.HTTP_400_BAD_REQUEST,
            message="Error",
            warnings=[warning],
        )
        assert len(response.warnings) == 1
        assert response.warnings[0].code == "comment_ignored"


class TestProviderMetadata:
    """Tests for ProviderMetadata model."""

    def test_metadata_fields(self):
        metadata = ProviderMetadata(
            record_id="abc123",
            request_id="req-xyz",
            zone_id="zone-1",
            extra={"cf_ray": "ray-id"},
        )
        assert metadata.record_id == "abc123"
        assert metadata.request_id == "req-xyz"
        assert metadata.zone_id == "zone-1"
        assert metadata.extra == {"cf_ray": "ray-id"}

    def test_metadata_optional_fields(self):
        metadata = ProviderMetadata()
        assert metadata.record_id is None
        assert metadata.request_id is None
        assert metadata.zone_id is None
        assert metadata.extra is None
