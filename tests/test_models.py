"""Tests for data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ddns_gateway.models import (
    DDNSResponse,
    DebugInfo,
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
    UpstreamInfo,
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


class TestDDNSResponseFactoryMethods:
    """Tests for DDNSResponse.success() and DDNSResponse.error() factory methods."""

    # ----- Separate parameter style -----

    def test_success_with_separate_params(self):
        """Test success() with zone, record_type, record_name."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
        )
        assert response.status == "success"
        assert response.record.zone == "example.com"
        assert response.record.type == "A"
        assert response.record.name == "home"

    def test_error_with_separate_params(self):
        """Test error() with zone, record_type, record_name."""
        response = DDNSResponse.error(
            errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
        )
        assert response.status == "error"
        assert response.record.zone == "example.com"

    # ----- Single ErrorModel / WarningModel -----

    def test_error_with_single_error_model(self):
        """Test error() accepts single ErrorModel (not list)."""
        response = DDNSResponse.error(
            errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
            provider="cloudflare",
            record=RecordInfo(zone="example.com", type="A", name="home"),
        )
        assert len(response.errors) == 1
        assert response.errors[0].code == "ZONE_NOT_FOUND"

    def test_success_with_single_warning_model(self):
        """Test success() accepts single WarningModel (not list)."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            record=RecordInfo(zone="example.com", type="A", name="home"),
            warnings=WarningModel(
                code=WarningCode.PROXIED_IGNORED,
                message="Proxied ignored",
            ),
        )
        assert len(response.warnings) == 1
        assert response.warnings[0].code == "PROXIED_IGNORED"

    # ----- Internal ResultInfo building -----

    def test_success_builds_result_from_effective_upstream(self):
        """Test success() builds ResultInfo from effective and upstream."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            effective=EffectiveValues(value="1.2.3.4", ttl=600),
            upstream=UpstreamInfo(record_id="rec123"),
            previous_value="5.6.7.8",
        )
        assert response.result is not None
        assert response.result.effective.value == "1.2.3.4"
        assert response.result.upstream.record_id == "rec123"
        assert response.result.previous_value == "5.6.7.8"

    def test_success_result_takes_priority(self):
        """Test that pre-built result takes priority over separate params."""
        pre_built = ResultInfo(effective=EffectiveValues(value="pre-built"))
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            result=pre_built,
            effective=EffectiveValues(value="ignored"),  # should be ignored
        )
        assert response.result.effective.value == "pre-built"

    # ----- Internal DebugInfo building -----

    def test_success_builds_debug_from_include_flag(self):
        """Test success() builds DebugInfo when include_debug_info=True."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            include_debug_info=True,
            raw_input={"key": "value"},
            normalized={"normalized_key": "normalized_value"},
        )
        assert response.debug is not None
        assert response.debug.raw_input == {"key": "value"}
        assert response.debug.normalized == {"normalized_key": "normalized_value"}

    def test_success_debug_takes_priority(self):
        """Test that pre-built debug takes priority over separate params."""
        pre_built = DebugInfo(raw_input={"pre": "built"})
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            debug=pre_built,
            include_debug_info=True,  # should be ignored
            raw_input={"ignored": "value"},  # should be ignored
        )
        assert response.debug.raw_input == {"pre": "built"}

    def test_error_builds_debug_from_include_flag(self):
        """Test error() builds DebugInfo when include_debug_info=True."""
        response = DDNSResponse.error(
            errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            include_debug_info=True,
            raw_input={"key": "value"},
            normalized=None,  # can be None for errors before normalization
        )
        assert response.debug is not None
        assert response.debug.raw_input == {"key": "value"}
        assert response.debug.normalized is None

    # ----- Parameter priority -----

    def test_success_record_takes_priority_over_separate_params(self):
        """Test that RecordInfo takes priority over zone/record_type/record_name."""
        record = RecordInfo(zone="priority.com", type="AAAA", name="priority")
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            record=record,
            zone="ignored.com",  # should be ignored
            record_type="A",  # should be ignored
            record_name="ignored",  # should be ignored
        )
        assert response.record.zone == "priority.com"
        assert response.record.type == "AAAA"
        assert response.record.name == "priority"

    def test_error_record_takes_priority_over_separate_params(self):
        """Test that RecordInfo takes priority in error() as well."""
        record = RecordInfo(zone="priority.com", type="AAAA", name="priority")
        response = DDNSResponse.error(
            errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
            provider="cloudflare",
            record=record,
            zone="ignored.com",  # should be ignored
            record_type="A",  # should be ignored
            record_name="ignored",  # should be ignored
        )
        assert response.record.zone == "priority.com"

    # ----- ValueError tests -----

    def test_success_raises_without_record_info(self):
        """Test success() raises ValueError when RecordInfo cannot be built."""
        with pytest.raises(ValueError, match="Must provide either"):
            DDNSResponse.success(
                action="created",
                provider="cloudflare",
                # Neither record nor zone/record_type/record_name provided
            )

    def test_success_raises_with_partial_params(self):
        """Test success() raises ValueError with incomplete separate params."""
        with pytest.raises(ValueError, match="Must provide either"):
            DDNSResponse.success(
                action="created",
                provider="cloudflare",
                zone="example.com",
                record_type="A",
                # record_name missing
            )

    def test_error_raises_without_record_info(self):
        """Test error() raises ValueError when RecordInfo cannot be built."""
        with pytest.raises(ValueError, match="Must provide either"):
            DDNSResponse.error(
                errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
                provider="cloudflare",
            )

    def test_error_raises_with_partial_params(self):
        """Test error() raises ValueError with incomplete separate params."""
        with pytest.raises(ValueError, match="Must provide either"):
            DDNSResponse.error(
                errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
                provider="cloudflare",
                zone="example.com",
                # record_type and record_name missing
            )

    # ----- Ensure no debug when include_debug_info=False -----

    def test_success_no_debug_when_flag_false(self):
        """Test success() doesn't build debug when include_debug_info=False."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            include_debug_info=False,
            raw_input={"key": "value"},
        )
        assert response.debug is None

    def test_success_no_debug_when_raw_input_none(self):
        """Test success() doesn't build debug when raw_input is None."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            include_debug_info=True,
            raw_input=None,
        )
        assert response.debug is None

    # ----- Ensure no result when neither effective nor upstream -----

    def test_success_no_result_when_no_data(self):
        """Test success() doesn't build result when neither effective nor upstream."""
        response = DDNSResponse.success(
            action="deleted",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            # No effective, upstream, or result provided
        )
        assert response.result is None


class TestDebugInfoExtra:
    """Tests for DebugInfo extra field."""

    def test_debug_info_with_extra(self):
        """Test DebugInfo with extra field."""
        debug = DebugInfo(
            raw_input={"zone": "example.com"},
            normalized={"zone": "example.com"},
            extra={"custom_key": "custom_value", "request_time_ms": 123},
        )
        assert debug.raw_input == {"zone": "example.com"}
        assert debug.normalized == {"zone": "example.com"}
        assert debug.extra == {"custom_key": "custom_value", "request_time_ms": 123}

    def test_debug_info_extra_defaults_to_none(self):
        """Test DebugInfo extra field defaults to None."""
        debug = DebugInfo(raw_input={"zone": "example.com"})
        assert debug.extra is None

    def test_success_builds_debug_with_extra(self):
        """Test success() builds DebugInfo with extra field."""
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            include_debug_info=True,
            raw_input={"key": "value"},
            normalized={"normalized_key": "normalized_value"},
            extra={"debug_hint": "some hint", "trace_id": "abc123"},
        )
        assert response.debug is not None
        assert response.debug.raw_input == {"key": "value"}
        assert response.debug.normalized == {"normalized_key": "normalized_value"}
        assert response.debug.extra == {"debug_hint": "some hint", "trace_id": "abc123"}

    def test_error_builds_debug_with_extra(self):
        """Test error() builds DebugInfo with extra field."""
        response = DDNSResponse.error(
            errors=ErrorModel(code=ErrorCode.ZONE_NOT_FOUND, message="Not found"),
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            include_debug_info=True,
            raw_input={"key": "value"},
            normalized=None,
            extra={"error_context": "additional info"},
        )
        assert response.debug is not None
        assert response.debug.raw_input == {"key": "value"}
        assert response.debug.normalized is None
        assert response.debug.extra == {"error_context": "additional info"}

    def test_success_extra_ignored_when_debug_prebuilt(self):
        """Test that extra is ignored when pre-built debug is provided."""
        pre_built = DebugInfo(
            raw_input={"pre": "built"},
            extra={"prebuilt_extra": "value"},
        )
        response = DDNSResponse.success(
            action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record_name="home",
            debug=pre_built,
            include_debug_info=True,
            raw_input={"ignored": "value"},
            extra={"ignored_extra": "should not appear"},
        )
        assert response.debug.raw_input == {"pre": "built"}
        assert response.debug.extra == {"prebuilt_extra": "value"}
