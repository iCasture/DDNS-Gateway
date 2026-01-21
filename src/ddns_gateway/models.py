"""
Data models for DDNS Gateway.

This module defines the core data structures used throughout the application,
including request/response models, enumerations for providers and record types,
and configuration models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Self, overload
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
    PROXIED_IGNORED : str
        Cloudflare proxied parameter ignored for non-A/AAAA/CNAME record type.
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
    PROXIED_IGNORED = "PROXIED_IGNORED"
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
    # 401 Unauthorized - Missing/invalid auth
    ErrorCode.MISSING_AUTH_TOKEN: st_status.HTTP_401_UNAUTHORIZED,
    ErrorCode.INVALID_AUTH_TOKEN: st_status.HTTP_401_UNAUTHORIZED,
    # 403 Forbidden - Missing/invalid upstream credentials
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


class SingleflightInfo(BaseModel):
    """
    Singleflight status information.

    Included in meta when a singleflight wait timeout occurs.

    Attributes
    ----------
    in_flight : bool
        Whether another request is currently in progress.
    in_flight_age_sec : float
        How long the in-flight request has been running (seconds).
    retry_after_sec : float
        Suggested time to wait before retrying (seconds).
    """

    in_flight: bool
    in_flight_age_sec: float
    retry_after_sec: float


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
    singleflight : SingleflightInfo | None
        Singleflight status information (if singleflight wait timeout occurs).
    """

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )
    dedupe: DedupeInfo | None = None
    singleflight: SingleflightInfo | None = None


class DebugInfo(BaseModel):
    """
    Debug information for troubleshooting.

    Only included when response.include_debug_info is enabled.

    Attributes
    ----------
    raw_input : dict[str, Any]
        The raw input parameters before normalization. Required.
    normalized : dict[str, Any] | None
        The normalized parameters used for the operation. May be None if
        an error occurred before normalization.
    extra : dict[str, Any] | None
        Additional custom debug information for troubleshooting. May contain
        any key-value pairs useful for diagnosing issues.
    """

    raw_input: dict[str, Any]
    normalized: dict[str, Any] | None = None
    extra: dict[str, Any] | None = None


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
        The effective record values after the operation. Required for
        create/update/unchanged actions, None for delete actions.
    upstream : UpstreamInfo | None
        Upstream provider operation details. May be None when record_id
        is not available (e.g., some deduped responses).
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
        Whether the upstream provider API was called (including read-only queries).
        `True`: Called upstream API (find/create/update/delete).
        `False`: No upstream call (cache hit or error before upstream call).
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
    def success(  # noqa: PLR0913
        cls,
        action: ActionType,
        provider: str,
        *,
        # # # # # # #
        # Record-related
        # # # # # # #
        # Pre-built RecordInfo object
        record: RecordInfo | None = None,
        # Separate params to build RecordInfo
        zone: str | None = None,
        record_type: str | None = None,
        record_name: str | None = None,
        # # # # # # #
        # Result-related
        # # # # # # #
        # Pre-built ResultInfo object
        result: ResultInfo | None = None,
        # Separate params to build ResultInfo
        effective: EffectiveValues | None = None,
        upstream: UpstreamInfo | None = None,
        previous_value: str | None = None,
        # # # # # # #
        # Debug-related
        # # # # # # #
        include_debug_info: bool = False,
        # Pre-built DebugInfo object
        debug: DebugInfo | None = None,
        # Separate params to build DebugInfo
        raw_input: dict[str, Any] | None = None,
        normalized: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        # # # # # # #
        # Other fields
        # # # # # # #
        upstream_called: bool = True,
        warnings: WarningModel | list[WarningModel] | None = None,
        meta: ResponseMeta | None = None,
    ) -> Self:
        """
        Create a successful response (DDNSResponse).

        This factory builds a DDNSResponse with ``status="success"`` and a required
        RecordInfo. It supports flexible inputs for RecordInfo, ResultInfo, ``warnings``,
        and DebugInfo.

        RecordInfo input styles
        -----------------------
        RecordInfo is **required**. Provide it in one of the following ways:

        1. **Composite object style** (recommended for tests / callers that already
           have a RecordInfo instance):

           >>> DDNSResponse.success(
           ...     action="created",
           ...     provider="cloudflare",
           ...     record=RecordInfo(zone="example.com", type="A", name="home"),
           ... )

           When ``record`` is provided, the separate parameters ``zone``,
           ``record_type``, and ``record_name`` are ignored.

        2. **Separate parameter style** (recommended for service layer):

           >>> DDNSResponse.success(
           ...     action="created",
           ...     provider="cloudflare",
           ...     zone="example.com",
           ...     record_type="A",
           ...     record_name="home",
           ... )

           In this mode, all three of ``zone``, ``record_type``, and ``record_name``
           must be provided, and ``record`` must be ``None`` (default).

        ResultInfo behavior
        -------------------
        ResultInfo is optional and represents the outcome of the operation. It can be
        provided in two ways:

        1. **Composite object style**: pass ``result=ResultInfo(...)`` directly.

        2. **Construct internally**: provide one or more of the following parameters:
        ``effective``, ``upstream``, and (optionally) ``previous_value``.

        Semantics of ResultInfo fields:

        - ``effective`` represents the resulting record values and is present for
          create, update, and unchanged operations.
        - ``upstream`` contains provider-side identifiers (e.g., record ID, zone ID)
          when available.
        - ``previous_value`` is only meaningful for update operations and **must**
          be accompanied by ``effective``.

        When ``result`` is provided, it takes priority and all separate ResultInfo
        parameters are ignored.

        Providing ``previous_value`` without ``effective`` (and without a pre-built
        ``result``) is considered invalid and raises ``ValueError``.

        Warnings normalization
        ----------------------
        - ``warnings`` accepts ``None``, a single WarningModel, or a list of WarningModel.
        Internally it is always stored as a list.

        DebugInfo behavior (gated by ``include_debug_info``)
        ----------------------------------------------------
        Debug info is optional and is only included when ``include_debug_info`` is ``True``.
        It can be provided in two ways:

        1. **Composite object style**: pass ``debug=DebugInfo(...)`` directly.

        2. **Construct internally**: set ``include_debug_info=True`` and provide
        ``raw_input`` (``normalized`` and ``extra`` are optional). DebugInfo is only
        constructed when ``include_debug_info`` is ``True`` *and* ``raw_input`` is not
        ``None``.

        When ``include_debug_info`` is ``True`` and ``debug`` is provided, it takes
        priority and ``raw_input``/``normalized``/``extra`` are ignored.

        Parameters
        ----------
        action : ActionType
            The action taken: "created", "updated", "unchanged", "deleted",
            or "deduped".
        provider : str
            The DNS provider name (e.g., "cloudflare", "aliyun", "tencent").

        record : RecordInfo | None, optional
            Pre-built record info object. If provided, ``zone``, ``record_type``,
            ``record_name`` are ignored.
        zone : str | None, optional
            DNS zone (e.g., "example.com"). Required if ``record`` is None.
        record_type : str | None, optional
            Record type (e.g., "A", "AAAA"). Required if ``record`` is None.
        record_name : str | None, optional
            Record name (e.g., "home", "@"). Required if ``record`` is None.

        result : ResultInfo | None, optional
            Pre-built result info. If provided, ``effective``, ``upstream``,
            ``previous_value`` are ignored.
        effective : EffectiveValues | None, optional
            Effective values after the operation. Used to build ``result`` internally.
        upstream : UpstreamInfo | None, optional
            Upstream provider info. Used to build ``result`` internally.
        previous_value : str | None, optional
            Previous record value for update operations. Requires ``effective`` when
            building ResultInfo internally.

        include_debug_info : bool, optional
            Whether to include debug info (default ``False``).
        debug : DebugInfo | None, optional
            Pre-built debug info. If provided, ``raw_input`` and ``normalized`` are ignored.
            Used only when ``include_debug_info`` is ``True``.
        raw_input : dict[str, Any] | None, optional
            Raw input for debug info. Required if ``include_debug_info`` is ``True``
            and ``debug`` is not provided.
        normalized : dict[str, Any] | None, optional
            Normalized input for debug info. Optional; may be ``None`` if normalization
            did not occur.
        extra : dict[str, Any] | None, optional
            Additional custom debug information. Optional; may contain any key-value
            pairs useful for diagnosing issues.

        upstream_called : bool, optional
            Whether upstream API was called before the error (default ``True``).
            Only False for cache hits (``action="deduped"``).
        warnings : WarningModel | list[WarningModel] | None, optional
            Warning(s) to include. Internally normalized to a list.
        meta : ResponseMeta | None, optional
            Response metadata. If ``None``, a new ResponseMeta is created.

        Returns
        -------
        DDNSResponse
            A success response instance (``status="success"``), with ``warnings`` always stored as a list.

        Raises
        ------
        ValueError
            If RecordInfo cannot be built (i.e., neither ``record`` nor a complete
            set of (``zone``, ``record_type``, ``record_name``) is provided, or if
            ``previous_value`` is provided without ``effective`` when building
            ResultInfo internally.
        """
        # 1. Normalize warnings to list format
        # success() accepts either a single WarningModel, a list, or None.
        # Internally, we always store warnings as a list.
        if isinstance(warnings, list):
            _warnings = warnings
        elif warnings is not None:
            _warnings = [warnings]
        else:
            _warnings = []

        # 2. Build RecordInfo (prefer pre-built object, fallback to separate params)
        # RecordInfo is required and all its fields (zone, type, name) are mandatory,
        # so we must have either a complete object or all three separate params.
        if record is not None:
            _record = record
        elif zone is not None and record_type is not None and record_name is not None:
            _record = RecordInfo(zone=zone, type=record_type, name=record_name)
        else:
            msg = "Must provide either 'record' or all of 'zone', 'record_type', 'record_name'."
            raise ValueError(msg)

        # 3. Build ResultInfo (prefer pre-built object, fallback to separate params)
        # ResultInfo is optional. We only build it when meaningful data exists.
        #
        # Semantics:
        # - effective: present for create/update/unchanged (the resulting record values)
        # - upstream: present when provider-side identifiers (e.g., record_id, zone_id) are available
        # - previous_value: only meaningful for update operations and MUST be accompanied
        #   by effective; providing previous_value without effective is considered invalid
        #
        # Therefore:
        # - Checking (effective or upstream) is sufficient; previous_value alone
        #   would never occur without effective.
        # - If previous_value is provided without effective (and no pre-built result),
        #   raise ValueError to avoid silently discarding invalid data.
        _result: ResultInfo | None = result

        if _result is None:
            if effective is None and previous_value is not None:
                msg = "'previous_value' requires 'effective' when building ResultInfo."
                raise ValueError(msg)

            if effective is not None or upstream is not None:
                _result = ResultInfo(
                    effective=effective,
                    upstream=upstream,
                    previous_value=previous_value,
                )

        # 4. Build DebugInfo (prefer pre-built object, fallback to separate params)
        # DebugInfo is optional and only included when explicitly requested.
        # - raw_input: required field in DebugInfo (no raw_input = no debug info)
        # - normalized: optional, may be None if error occurred before normalization
        # - extra: optional, may contain any custom debug information
        _debug: DebugInfo | None = None
        if include_debug_info:
            _debug = debug
            if _debug is None and raw_input is not None:
                _debug = DebugInfo(
                    raw_input=raw_input, normalized=normalized, extra=extra
                )

        return cls(
            status="success",
            action=action,
            upstream_called=upstream_called,
            provider=provider,
            record=_record,
            result=_result,
            warnings=_warnings,
            errors=[],
            meta=meta or ResponseMeta(),
            debug=_debug,
        )

    @classmethod
    def error(  # noqa: PLR0913
        cls,
        errors: ErrorModel | list[ErrorModel],
        provider: str,
        *,
        # Record-related
        # # # # # # #
        # Pre-built RecordInfo object
        record: RecordInfo | None = None,
        # Separate params to build RecordInfo
        zone: str | None = None,
        record_type: str | None = None,
        record_name: str | None = None,
        # # # # # # #
        # Debug-related
        # # # # # # #
        include_debug_info: bool = False,
        # Pre-built DebugInfo object
        debug: DebugInfo | None = None,
        # Separate params to build DebugInfo
        raw_input: dict[str, Any] | None = None,
        normalized: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        # # # # # # #
        # Other fields
        # # # # # # #
        upstream_called: bool = False,
        warnings: WarningModel | list[WarningModel] | None = None,
        meta: ResponseMeta | None = None,
    ) -> Self:
        """
        Create an error response (DDNSResponse).

        This factory builds a DDNSResponse with ``status="error"`` and a required
        RecordInfo. It supports flexible inputs for ``errors``, ``warnings``,
        RecordInfo, and DebugInfo.

        RecordInfo input styles
        -----------------------
        RecordInfo is **required**. Provide it in one of the following ways:

        1. **Composite object style** (recommended for tests / callers that already
           have a RecordInfo instance):

           >>> DDNSResponse.error(
           ...     errors=ErrorModel(code="ZONE_NOT_FOUND", message="Zone not found"),
           ...     provider="cloudflare",
           ...     record=RecordInfo(zone="example.com", type="A", name="home"),
           ... )

           When ``record`` is provided, the separate parameters ``zone``,
           ``record_type``, and ``record_name`` are ignored.

        2. **Separate parameter style** (recommended for service layer):

           >>> DDNSResponse.error(
           ...     errors=ErrorModel(code="ZONE_NOT_FOUND", message="Zone not found"),
           ...     provider="cloudflare",
           ...     zone="example.com",
           ...     record_type="A",
           ...     record_name="home",
           ... )

           In this mode, all three of ``zone``, ``record_type``, and ``record_name``
           must be provided, and ``record`` must be ``None`` (default).

        Errors and warnings normalization
        ---------------------------------
        - ``errors`` accepts either a single ErrorModel or a list of ErrorModel.
          Internally it is always stored as a list.

        - ``warnings`` accepts ``None``, a single WarningModel, or a list of WarningModel.
          Internally it is always stored as a list.

        DebugInfo behavior (gated by ``include_debug_info``)
        ----------------------------------------------------
        Debug info is optional and is only included when ``include_debug_info`` is ``True``.
        It can be provided in two ways:

        1. **Composite object style**: pass ``debug=DebugInfo(...)`` directly.

        2. **Construct internally**: set ``include_debug_info=True`` and provide
           ``raw_input`` (``normalized`` and ``extra`` are optional). DebugInfo is only
           constructed when ``include_debug_info`` is ``True`` **and** ``raw_input`` is
           not ``None``.

        When ``include_debug_info`` is ``True`` and ``debug`` is provided, it takes
        priority and ``raw_input``/``normalized``/``extra`` are ignored.

        Parameters
        ----------
        errors : ErrorModel | list[ErrorModel]
            Error(s) to include in the response. A single ErrorModel is wrapped into
            a one-element list.
        provider : str
            The DNS provider name.

        record : RecordInfo | None, optional
            Pre-built record info object. If provided, ``zone``, ``record_type``,
            ``record_name`` are ignored.
        zone : str | None, optional
            DNS zone (e.g., "example.com"). Required if ``record`` is ``None``.
        record_type : str | None, optional
            Record type (e.g., "A", "AAAA"). Required if ``record`` is ``None``.
        record_name : str | None, optional
            Record name (e.g., "home", "@"). Required if ``record`` is ``None``.

        include_debug_info : bool, optional
            Whether to include debug info (default ``False``).
        debug : DebugInfo | None, optional
            Pre-built debug info. If provided, ``raw_input`` and ``normalized`` are ignored.
            Used only when ``include_debug_info`` is ``True``.
        raw_input : dict[str, Any] | None, optional
            Raw input for debug info. Required if ``include_debug_info`` is ``True``
            and ``debug`` is not provided.
        normalized : dict[str, Any] | None, optional
            Normalized input for debug info. Optional; may be ``None`` if
            normalization did not happen before the error.
        extra : dict[str, Any] | None, optional
            Additional custom debug information. Optional; may contain any key-value
            pairs useful for diagnosing issues.

        upstream_called : bool, optional
            Whether upstream API was called before the error (default ``False``).
        warnings : WarningModel | list[WarningModel] | None, optional
            Warning(s) to include. Internally normalized to a list.
        meta : ResponseMeta | None, optional
            Response metadata. If ``None``, a new ResponseMeta is created.

        Returns
        -------
        DDNSResponse
            An error response instance (``status="error"``), with ``errors`` always
            a list and ``warnings`` always a list.


        Raises
        ------
        ValueError
            If RecordInfo cannot be built (i.e., neither ``record`` nor a complete
            set of (``zone``, ``record_type``, ``record_name``) is provided).
        """
        # 1. Normalize errors to list format
        # error() accepts either a single ErrorModel or a list for convenience.
        # Internally, we always store errors as a list.
        _errors = errors if isinstance(errors, list) else [errors]

        # 2. Normalize warnings to list format
        # error() accepts either a single WarningModel, a list, or None.
        # Internally, we always store warnings as a list.
        if isinstance(warnings, list):
            _warnings = warnings
        elif warnings is not None:
            _warnings = [warnings]
        else:
            _warnings = []

        # 3. Build RecordInfo (prefer pre-built object, fallback to separate params)
        # RecordInfo is required and all its fields (zone, type, name) are mandatory,
        # so we must have either a complete object or all three separate params.
        if record is not None:
            _record = record
        elif zone is not None and record_type is not None and record_name is not None:
            _record = RecordInfo(zone=zone, type=record_type, name=record_name)
        else:
            msg = "Must provide either 'record' or all of 'zone', 'record_type', 'record_name'."
            raise ValueError(msg)

        # 4. Build DebugInfo (prefer pre-built object, fallback to separate params)
        # DebugInfo is optional and only included when explicitly requested.
        # - raw_input: required field in DebugInfo (no raw_input = no debug info)
        # - normalized: optional, may be None if error occurred before normalization
        # - extra: optional, may contain any custom debug information
        _debug: DebugInfo | None = None
        if include_debug_info:
            _debug = debug
            if _debug is None and raw_input is not None:
                _debug = DebugInfo(
                    raw_input=raw_input, normalized=normalized, extra=extra
                )

        return cls(
            status="error",
            action=None,
            upstream_called=upstream_called,
            provider=provider,
            record=_record,
            result=None,
            warnings=_warnings,
            errors=_errors,
            meta=meta or ResponseMeta(),
            debug=_debug,
        )

    @classmethod
    def from_dedupe_dict(
        cls,
        resp_dict: dict[str, Any],
        window_seconds: int,
        *,
        extra_warnings: list[WarningModel] | None = None,
        include_debug_info: bool = False,
        raw_input: dict[str, Any] | None = None,
        normalized: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Self:
        """
        Create a response from a dedupe cache hit dictionary.

        Parameters
        ----------
        resp_dict : dict[str, Any]
            Response dictionary produced by ``build_dedupe_response_dict``.
        window_seconds : int
            The dedupe window used for meta.dedupe.window_sec.
        extra_warnings : list[WarningModel] | None, optional
            Additional warnings to append (e.g., validation warnings).
        include_debug_info : bool, optional
            Whether to include debug information in the response.
        raw_input : dict[str, Any] | None, optional
            Raw input dictionary for debug info.
        normalized : dict[str, Any] | None, optional
            Normalized dictionary for debug info.
        extra : dict[str, Any] | None, optional
            Additional custom debug information for troubleshooting.

        Returns
        -------
        DDNSResponse
            The deduped response.
        """
        result: ResultInfo | None = None
        if resp_dict.get("result"):
            upstream = None
            if resp_dict["result"].get("upstream"):
                upstream = UpstreamInfo(**resp_dict["result"]["upstream"])
            result = ResultInfo(
                effective=EffectiveValues(**resp_dict["result"]["effective"]),
                upstream=upstream,
                previous_value=resp_dict["result"].get("previous_value"),
            )

        debug: DebugInfo | None = None
        if include_debug_info and raw_input is not None:
            debug = DebugInfo(raw_input=raw_input, normalized=normalized, extra=extra)

        # Convert warnings to WarningModel objects (they may be dicts from dedupe cache)
        warnings_list: list[WarningModel] = []
        for w in resp_dict.get("warnings", []):
            if isinstance(w, WarningModel):
                warnings_list.append(w)
            elif isinstance(w, dict):
                warnings_list.append(WarningModel(**w))
            else:
                # Fallback: try to construct from whatever we have
                warnings_list.append(
                    WarningModel(**w.__dict__)
                    if hasattr(w, "__dict__")
                    else WarningModel(code=str(w), message=str(w)),
                )

        if extra_warnings:
            warnings_list.extend(extra_warnings)

        return cls(
            status=resp_dict["status"],
            action=resp_dict["action"],
            upstream_called=resp_dict["upstream_called"],
            provider=resp_dict["provider"],
            record=RecordInfo(**resp_dict["record"]),
            result=result,
            warnings=warnings_list,
            errors=resp_dict["errors"],
            meta=ResponseMeta(
                dedupe=DedupeInfo(
                    hit=True,
                    window_sec=window_seconds,
                ),
            ),
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
