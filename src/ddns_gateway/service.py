"""
Service layer for DDNS Gateway.

This module provides the core business logic for DNS record operations,
orchestrating the flow between normalization, provider calls, and response
building.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ddns_gateway.models import (
    DDNSResponse,
    EffectiveValues,
    ErrorCode,
    ErrorModel,
    RecordInfo,
    RecordType,
    ResponseMeta,
    ResultInfo,
    UpstreamInfo,
    WarningModel,
)
from ddns_gateway.normalize import (
    NormalizeError,
    comments_equal,
    normalize_comment,
    normalize_record,
    normalize_ttl,
    normalize_upstream_value,
    normalize_value,
    normalize_zone,
)
from ddns_gateway.types import DesiredState

if TYPE_CHECKING:
    from ddns_gateway.providers.base import BaseDNSProvider


logger = logging.getLogger(__name__)


# =============================================================================
# Helper Functions
# =============================================================================


def _build_error_response(
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    error: ErrorModel,
    *,
    warnings: list[WarningModel] | None = None,
) -> DDNSResponse:
    """
    Build an error DDNSResponse.

    Parameters
    ----------
    provider : str
        The DNS provider name.
    zone : str
        The DNS zone.
    record_type : str
        The record type.
    record : str
        The record name.
    error : ErrorModel
        The error to include.
    warnings : list[WarningModel] | None
        Optional warnings to include.

    Returns
    -------
    DDNSResponse
        The error response.
    """
    return DDNSResponse(
        status="error",
        action=None,
        upstream_called=False,
        provider=provider,
        record=RecordInfo(zone=zone, type=record_type, name=record),
        result=None,
        warnings=warnings or [],
        errors=[error],
        meta=ResponseMeta(),
        debug=None,
    )


def _build_success_response(
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    action: str,
    upstream_called: bool,  # noqa: FBT001
    *,
    effective: EffectiveValues | None = None,
    upstream: UpstreamInfo | None = None,
    previous_value: str | None = None,
    warnings: list[WarningModel] | None = None,
) -> DDNSResponse:
    """
    Build a success DDNSResponse.

    Parameters
    ----------
    provider : str
        The DNS provider name.
    zone : str
        The DNS zone.
    record_type : str
        The record type.
    record : str
        The record name.
    action : str
        The action taken.
    upstream_called : bool
        Whether the upstream API was called.
    effective : EffectiveValues | None
        The effective values after operation.
    upstream : UpstreamInfo | None
        The upstream operation info.
    previous_value : str | None
        The previous value (for updates).
    warnings : list[WarningModel] | None
        Optional warnings to include.

    Returns
    -------
    DDNSResponse
        The success response.
    """
    result = None
    if effective or upstream:
        result = ResultInfo(
            effective=effective,
            upstream=upstream,
            previous_value=previous_value,
        )

    return DDNSResponse(
        status="success",
        action=action,  # type: ignore[arg-type]
        upstream_called=upstream_called,
        provider=provider,
        record=RecordInfo(zone=zone, type=record_type, name=record),
        result=result,
        warnings=warnings or [],
        errors=[],
        meta=ResponseMeta(),
        debug=None,
    )


# =============================================================================
# Service Functions
# =============================================================================


async def upsert_record_service(
    provider_instance: BaseDNSProvider,
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    value: str,
    ttl: int | None,
    comment: str | None,
    proxied: bool | None,  # noqa: FBT001
    credentials: dict[str, str],
) -> DDNSResponse:
    """
    Upsert (create or update) a DNS record.

    Flow:
    1. Normalize all inputs
    2. [Reserved] Compute dedupe key
    3. [Reserved] Check dedupe cache -> short-circuit if hit
    4. Call provider.find_record()
    5. If not found: call provider.create_record()
    6. If found: compare -> call provider.update_record() if different,
       else return nochange
    7. [Reserved] Update dedupe cache
    8. Build and return DDNSResponse

    Parameters
    ----------
    provider_instance : BaseDNSProvider
        The provider instance to use.
    provider : str
        The DNS provider name (lowercase).
    zone : str
        The DNS zone (raw, will be normalized).
    record_type : str
        The record type (raw, will be validated).
    record : str
        The record name (raw, will be normalized).
    value : str
        The desired record value (raw, will be normalized).
    ttl : int | None
        The desired TTL (None for provider default).
    comment : str | None
        The desired comment (None for no comment).
    proxied : bool | None
        The desired Cloudflare proxy status (CF only, A/AAAA/CNAME).
    credentials : dict[str, str]
        Provider credentials.

    Returns
    -------
    DDNSResponse
        The operation response.
    """
    warnings: list[WarningModel] = []

    # -------------------------------------------------------------------------
    # Step 1: Normalize inputs
    # -------------------------------------------------------------------------
    try:
        norm_zone = normalize_zone(zone)
        norm_record = normalize_record(record)

        # Validate record type
        try:
            record_type_enum = RecordType(record_type.upper())
        except ValueError:
            return _build_error_response(
                provider=provider,
                zone=zone,
                record_type=record_type,
                record=record,
                error=ErrorModel(
                    code=ErrorCode.INVALID_RECORD_TYPE,
                    message=f"Invalid record type: {record_type}",
                    field="type",
                ),
            )

        norm_value = normalize_value(value, record_type_enum.value)
        norm_ttl = normalize_ttl(ttl)
        norm_comment = normalize_comment(comment)

    except NormalizeError as e:
        return _build_error_response(
            provider=provider,
            zone=zone,
            record_type=record_type,
            record=record,
            error=ErrorModel(
                code=e.code,
                message=e.message,
                field=e.field,
            ),
        )

    # -------------------------------------------------------------------------
    # Step 2-3: [Reserved] Dedupe cache check
    # -------------------------------------------------------------------------
    # TODO: Implement in Stage 4

    # -------------------------------------------------------------------------
    # Step 4: Find existing record
    # -------------------------------------------------------------------------
    try:
        existing = await provider_instance.find_record(
            zone=norm_zone,
            record=norm_record,
            record_type=record_type_enum,
            credentials=credentials,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: upsert] find_record failed: '%s'",
            e,
        )
        return _build_error_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            error=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to query existing record: {e}",
            ),
        )

    # Build desired state
    desired = DesiredState(
        value=norm_value,
        ttl=norm_ttl,
        comment=norm_comment,
        proxied=proxied,
    )

    # -------------------------------------------------------------------------
    # Step 5: Create new record if not found
    # -------------------------------------------------------------------------
    if existing is None:
        try:
            result = await provider_instance.create_record(
                zone=norm_zone,
                record=norm_record,
                record_type=record_type_enum,
                desired=desired,
                credentials=credentials,
            )
        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[service: upsert] create_record failed: '%s'",
                e,
            )
            return _build_error_response(
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record=norm_record,
                error=ErrorModel(
                    code=ErrorCode.UPSTREAM_API_ERROR,
                    message=f"Failed to create record: {e}",
                ),
            )

        if not result.success:
            return _build_error_response(
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record=norm_record,
                error=ErrorModel(
                    code=ErrorCode.UPSTREAM_API_ERROR,
                    message=result.message,
                ),
                warnings=result.warnings,
            )

        return _build_success_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            action="created",
            upstream_called=True,
            effective=EffectiveValues(
                value=norm_value,
                ttl=norm_ttl,
                comment=norm_comment,
                proxied=proxied,
            ),
            upstream=UpstreamInfo(
                record_id=result.record_id,
                zone_id=result.zone_id,
                raw_status=result.raw_status,
                http_status=result.http_status,
            ),
            warnings=result.warnings,
        )

    # -------------------------------------------------------------------------
    # Step 6: Update existing record if different
    # -------------------------------------------------------------------------
    # Normalize existing value for comparison
    existing_value = normalize_upstream_value(existing.value, record_type_enum.value)

    # Check if update is needed
    value_changed = existing_value != norm_value
    ttl_changed = norm_ttl is not None and existing.ttl != norm_ttl
    comment_changed = not comments_equal(existing.comment, norm_comment)
    proxied_changed = proxied is not None and existing.proxied != proxied

    if not (value_changed or ttl_changed or comment_changed or proxied_changed):
        # No change needed
        return _build_success_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            action="unchanged",
            upstream_called=False,
            effective=EffectiveValues(
                value=existing_value,
                ttl=existing.ttl,
                comment=existing.comment,
                proxied=existing.proxied,
            ),
            upstream=UpstreamInfo(
                record_id=existing.record_id,
                zone_id=existing.zone_id,
            ),
        )

    # Update record
    try:
        result = await provider_instance.update_record(
            zone=norm_zone,
            existing=existing,
            desired=desired,
            credentials=credentials,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: upsert] update_record failed: '%s'",
            e,
        )
        return _build_error_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            error=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to update record: {e}",
            ),
        )

    if not result.success:
        return _build_error_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            error=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=result.message,
            ),
            warnings=result.warnings,
        )

    return _build_success_response(
        provider=provider,
        zone=norm_zone,
        record_type=record_type_enum.value,
        record=norm_record,
        action="updated",
        upstream_called=True,
        effective=EffectiveValues(
            value=norm_value,
            ttl=norm_ttl if norm_ttl is not None else existing.ttl,
            comment=norm_comment if norm_comment is not None else existing.comment,
            proxied=proxied if proxied is not None else existing.proxied,
        ),
        upstream=UpstreamInfo(
            record_id=result.record_id or existing.record_id,
            zone_id=result.zone_id or existing.zone_id,
            raw_status=result.raw_status,
            http_status=result.http_status,
        ),
        previous_value=existing_value if value_changed else None,
        warnings=result.warnings,
    )


async def delete_record_service(
    provider_instance: BaseDNSProvider,
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    credentials: dict[str, str],
) -> DDNSResponse:
    """
    Delete a DNS record.

    Flow:
    1. Normalize inputs
    2. [Reserved] Compute dedupe key (value/ttl/comment/proxied = None)
    3. [Reserved] Check dedupe cache -> short-circuit if hit
    4. Call provider.find_record()
    5. If not found: return nochange (success)
    6. If found: call provider.delete_record()
    7. [Reserved] Update dedupe cache
    8. Build and return DDNSResponse

    Parameters
    ----------
    provider_instance : BaseDNSProvider
        The provider instance to use.
    provider : str
        The DNS provider name (lowercase).
    zone : str
        The DNS zone (raw, will be normalized).
    record_type : str
        The record type (raw, will be validated).
    record : str
        The record name (raw, will be normalized).
    credentials : dict[str, str]
        Provider credentials.

    Returns
    -------
    DDNSResponse
        The operation response.
    """
    # -------------------------------------------------------------------------
    # Step 1: Normalize inputs
    # -------------------------------------------------------------------------
    try:
        norm_zone = normalize_zone(zone)
        norm_record = normalize_record(record)

        # Validate record type
        try:
            record_type_enum = RecordType(record_type.upper())
        except ValueError:
            return _build_error_response(
                provider=provider,
                zone=zone,
                record_type=record_type,
                record=record,
                error=ErrorModel(
                    code=ErrorCode.INVALID_RECORD_TYPE,
                    message=f"Invalid record type: {record_type}",
                    field="type",
                ),
            )

    except NormalizeError as e:
        return _build_error_response(
            provider=provider,
            zone=zone,
            record_type=record_type,
            record=record,
            error=ErrorModel(
                code=e.code,
                message=e.message,
                field=e.field,
            ),
        )

    # -------------------------------------------------------------------------
    # Step 2-3: [Reserved] Dedupe cache check
    # -------------------------------------------------------------------------
    # TODO: Implement in Stage 4

    # -------------------------------------------------------------------------
    # Step 4: Find existing record
    # -------------------------------------------------------------------------
    try:
        existing = await provider_instance.find_record(
            zone=norm_zone,
            record=norm_record,
            record_type=record_type_enum,
            credentials=credentials,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: delete] find_record failed: '%s'",
            e,
        )
        return _build_error_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            error=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to query existing record: {e}",
            ),
        )

    # -------------------------------------------------------------------------
    # Step 5: Return nochange if not found
    # -------------------------------------------------------------------------
    if existing is None:
        return _build_success_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            action="unchanged",
            upstream_called=False,
        )

    # -------------------------------------------------------------------------
    # Step 6: Delete existing record
    # -------------------------------------------------------------------------
    try:
        result = await provider_instance.delete_record(
            zone=norm_zone,
            existing=existing,
            credentials=credentials,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: delete] delete_record failed: '%s'",
            e,
        )
        return _build_error_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            error=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to delete record: {e}",
            ),
        )

    if not result.success:
        return _build_error_response(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            error=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=result.message,
            ),
            warnings=result.warnings,
        )

    return _build_success_response(
        provider=provider,
        zone=norm_zone,
        record_type=record_type_enum.value,
        record=norm_record,
        action="deleted",
        upstream_called=True,
        upstream=UpstreamInfo(
            record_id=result.record_id or existing.record_id,
            zone_id=result.zone_id or existing.zone_id,
            raw_status=result.raw_status,
            http_status=result.http_status,
        ),
        warnings=result.warnings,
    )
