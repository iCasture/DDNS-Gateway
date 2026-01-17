"""Tests for types module."""

from __future__ import annotations

from ddns_gateway.models import WarningCode, WarningModel
from ddns_gateway.types import (
    DesiredState,
    ExistingRecord,
    RecordIdentity,
    UpstreamResult,
)


class TestRecordIdentity:
    """Tests for RecordIdentity dataclass."""

    def test_basic_creation(self):
        """Test creating a RecordIdentity."""
        identity = RecordIdentity(
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
        )
        assert identity.provider == "cloudflare"
        assert identity.zone == "example.com"
        assert identity.record_type == "A"
        assert identity.record == "home"

    def test_frozen_immutable(self):
        """Test that RecordIdentity is immutable (frozen)."""
        identity = RecordIdentity(
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
        )
        # Should raise FrozenInstanceError
        try:
            identity.provider = "aliyun"  # type: ignore[misc]
            raise AssertionError("Expected FrozenInstanceError")  # noqa: TRY003, EM101
        except AttributeError:
            pass

    def test_hashable(self):
        """Test that RecordIdentity is hashable (can be used in sets/dicts)."""
        identity1 = RecordIdentity(
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
        )
        identity2 = RecordIdentity(
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
        )
        identity3 = RecordIdentity(
            provider="aliyun",
            zone="example.com",
            record_type="A",
            record="home",
        )

        # Same identity should hash to same value
        assert hash(identity1) == hash(identity2)
        assert identity1 == identity2

        # Different identity should be distinguishable
        assert identity1 != identity3
        assert {identity1, identity2, identity3} == {identity1, identity3}


class TestExistingRecord:
    """Tests for ExistingRecord dataclass."""

    def test_basic_creation(self):
        """Test creating an ExistingRecord with minimal fields."""
        record = ExistingRecord(
            record_id="rec_123",
            zone_id=None,
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        assert record.record_id == "rec_123"
        assert record.zone_id is None
        assert record.value == "1.2.3.4"
        assert record.ttl == 300  # noqa: PLR2004
        assert record.comment is None
        assert record.proxied is None
        assert record.raw == {}

    def test_full_creation(self):
        """Test creating an ExistingRecord with all fields."""
        raw_data = {"id": "rec_123", "content": "1.2.3.4"}
        record = ExistingRecord(
            record_id="rec_123",
            zone_id="zone_456",
            value="1.2.3.4",
            ttl=3600,
            comment="My home IP",
            proxied=True,
            raw=raw_data,
        )
        assert record.record_id == "rec_123"
        assert record.zone_id == "zone_456"
        assert record.value == "1.2.3.4"
        assert record.ttl == 3600  # noqa: PLR2004
        assert record.comment == "My home IP"
        assert record.proxied is True
        assert record.raw == raw_data


class TestDesiredState:
    """Tests for DesiredState dataclass."""

    def test_minimal_creation(self):
        """Test creating a DesiredState with only value."""
        state = DesiredState(value="1.2.3.4")
        assert state.value == "1.2.3.4"
        assert state.ttl is None
        assert state.comment is None
        assert state.proxied is None

    def test_full_creation(self):
        """Test creating a DesiredState with all fields."""
        state = DesiredState(
            value="1.2.3.4",
            ttl=300,
            comment="Updated by script",
            proxied=False,
        )
        assert state.value == "1.2.3.4"
        assert state.ttl == 300  # noqa: PLR2004
        assert state.comment == "Updated by script"
        assert state.proxied is False


class TestUpstreamResult:
    """Tests for UpstreamResult dataclass."""

    def test_success_result(self):
        """Test creating a successful UpstreamResult."""
        result = UpstreamResult(
            success=True,
            action="created",
            message="Record created successfully",
            record_id="rec_123",
        )
        assert result.success is True
        assert result.action == "created"
        assert result.message == "Record created successfully"
        assert result.record_id == "rec_123"
        assert result.warnings == []

    def test_failure_result(self):
        """Test creating a failed UpstreamResult."""
        result = UpstreamResult(
            success=False,
            action="created",
            message="Failed to create record: API error",
        )
        assert result.success is False
        assert result.action == "created"
        assert result.message == "Failed to create record: API error"

    def test_result_with_warnings(self):
        """Test creating an UpstreamResult with warnings."""
        warnings = [
            WarningModel(
                code=WarningCode.PROXIED_IGNORED,
                message="Proxied ignored for TXT",
            ),
        ]
        result = UpstreamResult(
            success=True,
            action="updated",
            message="Record updated",
            warnings=warnings,
        )
        assert len(result.warnings) == 1
        assert result.warnings[0].code == WarningCode.PROXIED_IGNORED

    def test_result_with_all_fields(self):
        """Test creating an UpstreamResult with all optional fields."""
        result = UpstreamResult(
            success=True,
            action="updated",
            message="Record updated successfully",
            record_id="rec_123",
            zone_id="zone_456",
            request_id="req_789",
            previous_value="1.1.1.1",
            http_status=200,
            raw_status="success",
            extra={"cf_ray": "abc123"},
        )
        assert result.record_id == "rec_123"
        assert result.zone_id == "zone_456"
        assert result.request_id == "req_789"
        assert result.previous_value == "1.1.1.1"
        assert result.http_status == 200  # noqa: PLR2004
        assert result.raw_status == "success"
        assert result.extra == {"cf_ray": "abc123"}
