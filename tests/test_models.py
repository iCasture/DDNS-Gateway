"""Tests for data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ddns_gateway.models import (
    DDNSResponse,
    DNSProvider,
    EffectiveValues,
    ErrorCode,
    ErrorModel,
    ProviderMetadata,
    RecordInfo,
    RecordType,
    ResponseMeta,
    ResultInfo,
    UpdateRequest,
    UpsertRequest,
    WarningCode,
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


class TestWarningCode:
    """Tests for WarningCode enum."""

    def test_warning_code_values(self):
        assert WarningCode.ALI_COMMENT_UPDATE_FAILED == "ALI_COMMENT_UPDATE_FAILED"
        assert WarningCode.PROXIED_IGNORED == "PROXIED_IGNORED"
        assert WarningCode.DEDUPE_HIT_SHORTCIRCUIT == "DEDUPE_HIT_SHORTCIRCUIT"

    def test_warning_code_from_string(self):
        assert (
            WarningCode("QUERY_IGNORED_DUE_TO_BODY")
            == WarningCode.QUERY_IGNORED_DUE_TO_BODY
        )


class TestErrorCode:
    """Tests for ErrorCode enum."""

    def test_error_code_values(self):
        assert ErrorCode.VALIDATION_ERROR == "VALIDATION_ERROR"
        assert ErrorCode.INVALID_PROVIDER == "INVALID_PROVIDER"
        assert ErrorCode.UPSTREAM_API_ERROR == "UPSTREAM_API_ERROR"
        assert ErrorCode.INTERNAL_ERROR == "INTERNAL_ERROR"

    def test_error_code_from_string(self):
        assert ErrorCode("ZONE_NOT_FOUND") == ErrorCode.ZONE_NOT_FOUND


class TestErrorModel:
    """Tests for ErrorModel."""

    def test_error_model_basic(self):
        error = ErrorModel(
            code=ErrorCode.INVALID_IP_ADDRESS,
            message="Invalid IPv4 address format",
        )
        assert error.code == "INVALID_IP_ADDRESS"
        assert error.message == "Invalid IPv4 address format"
        assert error.field is None
        assert error.details is None

    def test_error_model_with_field(self):
        error = ErrorModel(
            code=ErrorCode.VALIDATION_ERROR,
            message="Field is required",
            field="value",
        )
        assert error.field == "value"

    def test_error_model_with_details(self):
        error = ErrorModel(
            code=ErrorCode.UPSTREAM_API_ERROR,
            message="Cloudflare API error",
            details={
                "http_status": 400,
                "raw_response": {"success": False, "errors": []},
            },
        )
        assert error.details is not None
        assert error.details["http_status"] == 400  # noqa: PLR2004


class TestUpsertRequest:
    """Tests for UpsertRequest model."""

    def test_valid_upsert_request(self):
        request = UpsertRequest(value="1.2.3.4")
        assert request.value == "1.2.3.4"
        assert request.ttl is None
        assert request.comment is None
        assert request.proxied is None

    def test_upsert_request_with_all_fields(self):
        request = UpsertRequest(
            value="1.2.3.4",
            ttl=600,
            comment="DDNS record",
            proxied=True,
        )
        assert request.value == "1.2.3.4"
        assert request.ttl == 600  # noqa: PLR2004
        assert request.comment == "DDNS record"
        assert request.proxied is True

    def test_upsert_request_invalid_ttl(self):
        with pytest.raises(ValidationError):
            UpsertRequest(value="1.2.3.4", ttl=0)

    def test_upsert_request_empty_value(self):
        with pytest.raises(ValidationError):
            UpsertRequest(value="")


class TestDDNSResponse:
    """Tests for DDNSResponse model."""

    def test_success_response(self):
        record = RecordInfo(zone="example.com", type="A", name="home")
        result = ResultInfo(
            effective=EffectiveValues(value="1.2.3.4", ttl=600),
        )
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            record=record,
            result=result,
        )
        assert response.status == "success"
        assert response.action == "created"
        assert response.upstream_called is True
        assert response.provider == "cloudflare"
        assert response.record.zone == "example.com"
        assert response.errors == []
        assert response.meta.request_id is not None

    def test_success_response_deduped(self):
        record = RecordInfo(zone="example.com", type="A", name="home")
        response = DDNSResponse.success(
            action="deduped",
            provider="cloudflare",
            record=record,
            upstream_called=False,
        )
        assert response.action == "deduped"
        assert response.upstream_called is False

    def test_error_response(self):
        record = RecordInfo(zone="example.com", type="A", name="home")
        errors = [
            ErrorModel(
                code=ErrorCode.ZONE_NOT_FOUND,
                message="Zone not found",
            ),
        ]
        response = DDNSResponse.error(
            errors=errors,
            provider="cloudflare",
            record=record,
        )
        assert response.status == "error"
        assert response.action is None
        assert response.upstream_called is False
        assert len(response.errors) == 1
        assert response.errors[0].code == "ZONE_NOT_FOUND"

    def test_to_plain_text(self):
        record = RecordInfo(zone="example.com", type="A", name="home")
        response = DDNSResponse.success(
            action="updated",
            provider="cloudflare",
            record=record,
            upstream_called=True,
        )
        text = response.to_plain_text()
        assert "status=success" in text
        assert "action=updated" in text
        assert "upstream_called=true" in text

    def test_response_with_warnings(self):
        record = RecordInfo(zone="example.com", type="A", name="home")
        warnings = [
            WarningModel(
                code=WarningCode.QUERY_IGNORED_DUE_TO_BODY,
                message="Query parameters ignored",
            ),
        ]
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            record=record,
            warnings=warnings,
        )
        assert len(response.warnings) == 1
        assert response.warnings[0].code == "QUERY_IGNORED_DUE_TO_BODY"


class TestResponseMeta:
    """Tests for ResponseMeta model."""

    def test_default_values(self):
        meta = ResponseMeta()
        assert meta.request_id is not None
        assert len(meta.request_id) == 36  # UUID format  # noqa: PLR2004
        assert meta.timestamp is not None
        assert meta.dedupe is None
