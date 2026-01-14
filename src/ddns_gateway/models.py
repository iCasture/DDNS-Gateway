"""
Data models for DDNS Gateway.

This module defines the core data structures used throughout the application,
including request/response models, enumerations for providers and record types,
and configuration models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field
from starlette import status as st_status

# =============================================================================
# Provider & Record Type Enums
# =============================================================================


class DNSProvider(StrEnum):
    """
    Supported DNS providers.

    Attributes
    ----------
    CLOUDFLARE : str
        CloudFlare DNS service.
    ALIYUN : str
        Alibaba Cloud DNS (alidns) service.
    TENCENT : str
        Tencent Cloud DNSPod service (China mainland only).
    """

    CLOUDFLARE = "cloudflare"
    ALIYUN = "aliyun"
    TENCENT = "tencent"


class RecordType(StrEnum):
    """
    Supported DNS record types.

    Attributes
    ----------
    A : str
        IPv4 address record.
    AAAA : str
        IPv6 address record.
    CNAME : str
        Canonical name (alias) record.
    TXT : str
        Text record.
    """

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"


# =============================================================================
# Warning & Error Code Enums
# =============================================================================


class WarningCode(StrEnum):
    """
    Warning codes for non-critical issues.

    These codes are machine-readable identifiers for warnings that don't
    prevent the operation from completing but may indicate suboptimal
    behavior or ignored parameters.

    Attributes
    ----------
    ALI_COMMENT_UPDATE_FAILED : str
        Aliyun provider failed to update record comment in second API call.
    CF_PROXIED_IGNORED_FOR_TXT : str
        Cloudflare proxied parameter ignored for TXT record type.
    PROXIED_IGNORED_FOR_NON_CF : str
        Proxied parameter ignored for non-Cloudflare provider.
    QUERY_IGNORED_DUE_TO_BODY : str
        Query parameters ignored because request body is present.
    DELETE_IGNORES_BODY_PARAMS : str
        DELETE request ignores body parameters.
    DELETE_IGNORES_QUERY_PARAMS : str
        DELETE request ignores query parameters.
    DEDUPE_HIT_SHORTCIRCUIT : str
        Request was short-circuited due to deduplication cache hit.
    FORMAT_OVERRIDES_ACCEPT : str
        Query format parameter overrides Accept header.
    RECORD_NOT_FOUND : str
        Record to be deleted was not found.
    """

    ALI_COMMENT_UPDATE_FAILED = "ALI_COMMENT_UPDATE_FAILED"
    CF_PROXIED_IGNORED_FOR_TXT = "CF_PROXIED_IGNORED_FOR_TXT"
    PROXIED_IGNORED_FOR_NON_CF = "PROXIED_IGNORED_FOR_NON_CF"
    QUERY_IGNORED_DUE_TO_BODY = "QUERY_IGNORED_DUE_TO_BODY"
    DELETE_IGNORES_BODY_PARAMS = "DELETE_IGNORES_BODY_PARAMS"
    DELETE_IGNORES_QUERY_PARAMS = "DELETE_IGNORES_QUERY_PARAMS"
    DEDUPE_HIT_SHORTCIRCUIT = "DEDUPE_HIT_SHORTCIRCUIT"
    FORMAT_OVERRIDES_ACCEPT = "FORMAT_OVERRIDES_ACCEPT"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"


class ErrorCode(StrEnum):
    """
    Error codes for critical issues.

    These codes are machine-readable identifiers for errors that prevent
    the operation from completing.

    Attributes
    ----------
    VALIDATION_ERROR : str
        General validation error.
    INVALID_PROVIDER : str
        Invalid or unsupported DNS provider.
    INVALID_RECORD_TYPE : str
        Invalid or unsupported record type.
    INVALID_ZONE_FORMAT : str
        Zone name has invalid format.
    INVALID_RECORD_FORMAT : str
        Record name has invalid format.
    INVALID_IP_ADDRESS : str
        Invalid IP address format.
    INVALID_DOMAIN_FORMAT : str
        Invalid domain name format.
    TXT_VALUE_TOO_LONG : str
        TXT record value exceeds maximum length.
    MISSING_AUTH_TOKEN : str
        Authentication token not provided.
    INVALID_AUTH_TOKEN : str
        Authentication token is invalid.
    MISSING_UPSTREAM_CREDENTIALS : str
        Upstream provider credentials not provided.
    INVALID_UPSTREAM_CREDENTIALS : str
        Upstream provider credentials are invalid.
    ZONE_NOT_FOUND : str
        DNS zone not found in provider.
    RECORD_NOT_FOUND : str
        DNS record not found in provider.
    MULTIPLE_RECORDS_FOUND : str
        Multiple matching records found (ambiguous).
    UPSTREAM_API_ERROR : str
        Upstream provider API returned an error.
    INTERNAL_ERROR : str
        Internal server error.
    SINGLEFLIGHT_WAIT_TIMEOUT : str
        Singleflight wait timeout - another request is in progress.
    """

    # Validation errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_PROVIDER = "INVALID_PROVIDER"
    INVALID_RECORD_TYPE = "INVALID_RECORD_TYPE"
    INVALID_ZONE_FORMAT = "INVALID_ZONE_FORMAT"
    INVALID_RECORD_FORMAT = "INVALID_RECORD_FORMAT"
    INVALID_IP_ADDRESS = "INVALID_IP_ADDRESS"
    INVALID_DOMAIN_FORMAT = "INVALID_DOMAIN_FORMAT"
    TXT_VALUE_TOO_LONG = "TXT_VALUE_TOO_LONG"

    # Authentication errors
    MISSING_AUTH_TOKEN = "MISSING_AUTH_TOKEN"  # noqa: S105
    INVALID_AUTH_TOKEN = "INVALID_AUTH_TOKEN"  # noqa: S105
    MISSING_UPSTREAM_CREDENTIALS = "MISSING_UPSTREAM_CREDENTIALS"
    INVALID_UPSTREAM_CREDENTIALS = "INVALID_UPSTREAM_CREDENTIALS"

    # Provider errors
    ZONE_NOT_FOUND = "ZONE_NOT_FOUND"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    MULTIPLE_RECORDS_FOUND = "MULTIPLE_RECORDS_FOUND"
    UPSTREAM_API_ERROR = "UPSTREAM_API_ERROR"

    # Internal errors
    INTERNAL_ERROR = "INTERNAL_ERROR"

    # Singleflight errors
    SINGLEFLIGHT_WAIT_TIMEOUT = "SINGLEFLIGHT_WAIT_TIMEOUT"


# =============================================================================
# Error Code to HTTP Status Mapping
# =============================================================================

ERROR_STATUS_MAP: dict[str, int] = {
    # 400 Bad Request - Validation errors (client error)
    ErrorCode.VALIDATION_ERROR: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_PROVIDER: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_RECORD_TYPE: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_ZONE_FORMAT: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_RECORD_FORMAT: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_IP_ADDRESS: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_DOMAIN_FORMAT: st_status.HTTP_400_BAD_REQUEST,
    ErrorCode.TXT_VALUE_TOO_LONG: st_status.HTTP_400_BAD_REQUEST,
    # 401 Unauthorized - Missing auth
    ErrorCode.MISSING_AUTH_TOKEN: st_status.HTTP_401_UNAUTHORIZED,
    # 403 Forbidden - Invalid auth
    ErrorCode.INVALID_AUTH_TOKEN: st_status.HTTP_403_FORBIDDEN,
    ErrorCode.MISSING_UPSTREAM_CREDENTIALS: st_status.HTTP_403_FORBIDDEN,
    ErrorCode.INVALID_UPSTREAM_CREDENTIALS: st_status.HTTP_403_FORBIDDEN,
    # 404 Not Found
    ErrorCode.ZONE_NOT_FOUND: st_status.HTTP_404_NOT_FOUND,
    ErrorCode.RECORD_NOT_FOUND: st_status.HTTP_404_NOT_FOUND,
    # 409 Conflict - Ambiguous
    ErrorCode.MULTIPLE_RECORDS_FOUND: st_status.HTTP_409_CONFLICT,
    # 500 Internal Server Error
    ErrorCode.INTERNAL_ERROR: st_status.HTTP_500_INTERNAL_SERVER_ERROR,
    # 502 Bad Gateway - Upstream API error
    ErrorCode.UPSTREAM_API_ERROR: st_status.HTTP_502_BAD_GATEWAY,
    # 504 Gateway Timeout - Singleflight wait timeout
    ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT: st_status.HTTP_504_GATEWAY_TIMEOUT,
}

# =============================================================================
# Request Models
# =============================================================================


class UpdateRequest(BaseModel):
    """
    DNS record update request model.

    Attributes
    ----------
    provider : DNSProvider
        The DNS provider to use.
    zone : str
        The DNS zone (root domain name, e.g., "example.com").
    record : str
        The host record name (e.g., "home", "@", "www").
    record_type : RecordType
        The type of DNS record (A, AAAA, CNAME, TXT).
    value : str
        The record value (IP address, target domain, text content, etc.).
    ttl : int | None
        Time to live in seconds, or None to use provider default.
    comment : str | None
        Optional comment/remark for the record.
    """

    provider: DNSProvider
    zone: str = Field(..., min_length=1, description="DNS zone (root domain name)")
    record: str = Field(..., min_length=1, description="Host record name")
    record_type: RecordType = Field(..., alias="type")
    value: str = Field(..., min_length=1, description="Record value")
    ttl: int | None = Field(default=None, ge=1, le=86400, description="TTL in seconds")
    comment: str | None = Field(
        default=None,
        max_length=500,
        description="Optional comment",
    )

    model_config = {"populate_by_name": True}


class UpsertRequest(BaseModel):
    """
    DNS record upsert (create or update) request body.

    Used for PUT /v1/ddns/{provider}/{zone}/{type}/{record} endpoint.
    Path parameters (provider, zone, type, record) are extracted from URL.

    Attributes
    ----------
    value : str
        The record value (required).
    ttl : int | None
        Time to live in seconds, or None to use provider default.
    comment : str | None
        Optional comment/remark for the record.
    proxied : bool | None
        Cloudflare proxy status (only for CF + A/AAAA/CNAME).
    """

    value: str = Field(..., min_length=1, description="Record value (required)")
    ttl: int | None = Field(default=None, ge=1, le=86400, description="TTL in seconds")
    comment: str | None = Field(
        default=None,
        max_length=500,
        description="Optional comment",
    )
    proxied: bool | None = Field(
        default=None,
        description="Cloudflare proxy status (CF only, A/AAAA/CNAME)",
    )


# =============================================================================
# Warning & Error Models
# =============================================================================


class WarningModel(BaseModel):
    """
    Warning message for non-critical issues.

    Attributes
    ----------
    code : str
        Machine-readable warning code (should be a WarningCode value).
    message : str
        Human-readable warning message.
    field : str | None
        The field that caused the warning (if applicable).
    details : dict[str, Any] | None
        Additional details about the warning.
    """

    code: str
    message: str
    field: str | None = None
    details: dict[str, Any] | None = None


class ErrorModel(BaseModel):
    """
    Error message for critical issues.

    Attributes
    ----------
    code : str
        Machine-readable error code (should be an ErrorCode value).
    message : str
        Human-readable error message.
    field : str | None
        The field that caused the error (if applicable).
    details : dict[str, Any] | None
        Additional details about the error (e.g., raw upstream response).
    """

    code: str
    message: str
    field: str | None = None
    details: dict[str, Any] | None = None


# =============================================================================
# Response Metadata Models
# =============================================================================


class ProviderMetadata(BaseModel):
    """
    Provider-specific metadata returned after an update.

    Attributes
    ----------
    record_id : str | None
        The DNS record ID from the provider.
    request_id : str | None
        The request ID from the provider API.
    zone_id : str | None
        The zone ID (CloudFlare specific).
    extra : dict[str, str] | None
        Additional provider-specific metadata.
    """

    record_id: str | None = None
    request_id: str | None = None
    zone_id: str | None = None
    extra: dict[str, str] | None = None


class DedupeInfo(BaseModel):
    """
    Deduplication cache information.

    Attributes
    ----------
    hit : bool
        Whether the request was a cache hit (short-circuited).
    window_sec : int
        The deduplication time window in seconds.
    """

    hit: bool
    window_sec: int


class ResponseMeta(BaseModel):
    """
    Response metadata containing request tracking and deduplication info.

    Attributes
    ----------
    request_id : str
        Unique identifier for this request.
    timestamp : str
        ISO 8601 timestamp of the response.
    dedupe : DedupeInfo | None
        Deduplication information (if dedupe is enabled).
    """

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )
    dedupe: DedupeInfo | None = None


class DebugInfo(BaseModel):
    """
    Debug information for troubleshooting.

    Only included when response.include_debug_info is enabled.

    Attributes
    ----------
    raw_input : dict[str, Any] | None
        The raw input parameters before normalization.
    normalized : dict[str, Any] | None
        The normalized parameters used for the operation.
    """

    raw_input: dict[str, Any] | None = None
    normalized: dict[str, Any] | None = None


# =============================================================================
# Response Data Models
# =============================================================================


class RecordInfo(BaseModel):
    """
    DNS record identification in response.

    Attributes
    ----------
    zone : str
        The DNS zone (root domain name).
    type : str
        The record type (A, AAAA, CNAME, TXT).
    name : str
        The host record name.
    """

    zone: str
    type: str
    name: str


class EffectiveValues(BaseModel):
    """
    Effective record values after the operation.

    Attributes
    ----------
    value : str
        The current record value.
    ttl : int | None
        The effective TTL value.
    comment : str | None
        The effective comment.
    proxied : bool | None
        The effective proxied status (Cloudflare only).
    """

    value: str
    ttl: int | None = None
    comment: str | None = None
    proxied: bool | None = None


class UpstreamInfo(BaseModel):
    """
    Upstream provider operation details.

    Attributes
    ----------
    record_id : str | None
        The DNS record ID from the provider.
    zone_id : str | None
        The zone ID (Cloudflare specific).
    raw_status : str | None
        The raw status string from the provider.
    http_status : int | None
        The HTTP status code from the upstream API.
    raw_response : dict[str, Any] | None
        The raw response from the provider (for debugging).
    """

    record_id: str | None = None
    zone_id: str | None = None
    raw_status: str | None = None
    http_status: int | None = None
    raw_response: dict[str, Any] | None = None


class ResultInfo(BaseModel):
    """
    Result details containing effective values and upstream info.

    Attributes
    ----------
    effective : EffectiveValues | None
        The effective record values after the operation.
    upstream : UpstreamInfo | None
        Upstream provider operation details.
    previous_value : str | None
        The previous record value (for action=updated).
    """

    effective: EffectiveValues | None = None
    upstream: UpstreamInfo | None = None
    previous_value: str | None = None


class ResponseData(BaseModel):
    """
    Data payload in the update response.

    Attributes
    ----------
    provider : str
        The DNS provider used.
    zone : str
        The DNS zone (root domain name).
    record : str
        The host record name.
    fqdn : str
        The fully qualified domain name.
    type : str
        The record type (A, AAAA, CNAME, TXT).
    value : str
        The current record value.
    ttl : int | None
        The TTL value.
    previous_value : str | None
        The previous record value (only for action=updated).
    """

    provider: str
    zone: str
    record: str
    fqdn: str
    type: str
    value: str
    ttl: int | None
    previous_value: str | None = None


# =============================================================================
# Main Response Models
# =============================================================================

# Action types for DDNSResponse
ActionType = Literal["created", "updated", "unchanged", "deleted", "deduped"]


class DDNSResponse(BaseModel):
    """
    DNS record operation response model (new unified format).

    This response format supports both JSON and plain text output.
    For plain text, status/action/upstream_called are returned as key=value pairs.

    Attributes
    ----------
    status : Literal["success", "error"]
        The overall status of the operation.
    action : ActionType | None
        The action taken: created, updated, unchanged, deleted, or deduped.
    upstream_called : bool
        Whether the upstream provider API was called.
    provider : str
        The DNS provider used.
    record : RecordInfo
        DNS record identification.
    result : ResultInfo | None
        Result details (effective values and upstream info).
    warnings : list[WarningModel]
        List of non-critical warnings.
    errors : list[ErrorModel]
        List of errors (for error responses).
    meta : ResponseMeta
        Response metadata (request_id, timestamp, dedupe info).
    debug : DebugInfo | None
        Debug information (only when enabled).
    """

    status: Literal["success", "error"]
    action: ActionType | None = None
    upstream_called: bool = False
    provider: str
    record: RecordInfo
    result: ResultInfo | None = None
    warnings: list[WarningModel] = Field(default_factory=list)
    errors: list[ErrorModel] = Field(default_factory=list)
    meta: ResponseMeta = Field(default_factory=ResponseMeta)
    debug: DebugInfo | None = None

    @classmethod
    def success(
        cls,
        action: ActionType,
        provider: str,
        record: RecordInfo,
        result: ResultInfo | None = None,
        upstream_called: bool = True,  # noqa: FBT001, FBT002
        warnings: list[WarningModel] | None = None,
        meta: ResponseMeta | None = None,
        debug: DebugInfo | None = None,
    ) -> DDNSResponse:
        """
        Create a successful response.

        Parameters
        ----------
        action : ActionType
            The action that was taken.
        provider : str
            The DNS provider used.
        record : RecordInfo
            DNS record identification.
        result : ResultInfo | None, optional
            Result details.
        upstream_called : bool, optional
            Whether upstream API was called (default True).
        warnings : list[WarningModel] | None, optional
            List of warnings.
        meta : ResponseMeta | None, optional
            Response metadata.
        debug : DebugInfo | None, optional
            Debug information.

        Returns
        -------
        DDNSResponse
            A success response instance.
        """
        return cls(
            status="success",
            action=action,
            upstream_called=upstream_called,
            provider=provider,
            record=record,
            result=result,
            warnings=warnings or [],
            errors=[],
            meta=meta or ResponseMeta(),
            debug=debug,
        )

    @classmethod
    def error(
        cls,
        errors: list[ErrorModel],
        provider: str,
        record: RecordInfo,
        upstream_called: bool = False,  # noqa: FBT001, FBT002
        warnings: list[WarningModel] | None = None,
        meta: ResponseMeta | None = None,
        debug: DebugInfo | None = None,
    ) -> DDNSResponse:
        """
        Create an error response.

        Parameters
        ----------
        errors : list[ErrorModel]
            List of errors.
        provider : str
            The DNS provider used.
        record : RecordInfo
            DNS record identification.
        upstream_called : bool, optional
            Whether upstream API was called (default False).
        warnings : list[WarningModel] | None, optional
            List of warnings.
        meta : ResponseMeta | None, optional
            Response metadata.
        debug : DebugInfo | None, optional
            Debug information.

        Returns
        -------
        DDNSResponse
            An error response instance.
        """
        return cls(
            status="error",
            action=None,
            upstream_called=upstream_called,
            provider=provider,
            record=record,
            result=None,
            warnings=warnings or [],
            errors=errors,
            meta=meta or ResponseMeta(),
            debug=debug,
        )

    def to_plain_text(self) -> str:
        """
        Convert response to plain text format for RouterOS compatibility.

        Returns
        -------
        str
            Plain text representation with key=value pairs.
        """
        lines = [
            f"status={self.status}",
            f"action={self.action or 'none'}",
            f"upstream_called={str(self.upstream_called).lower()}",
        ]
        return "\n".join(lines)
