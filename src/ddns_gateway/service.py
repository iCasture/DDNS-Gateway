"""
Service layer for DDNS Gateway.

This module provides the core business logic for DNS record operations,
orchestrating the flow between normalization, provider calls, and response
building.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ddns_gateway.dedupe import (
    build_deduped_response,
    compute_dedupe_key,
    create_cached_base,
)
from ddns_gateway.models import (
    DDNSResponse,
    DedupeInfo,
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
    from ddns_gateway.config import DedupeConfig
    from ddns_gateway.dedupe import DedupeCache
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
    *,
    dedupe_cache: DedupeCache | None = None,
    dedupe_config: DedupeConfig | None = None,
    timeout_sec: float | None = None,
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
    dedupe_cache : DedupeCache | None
        Optional dedupe cache for request deduplication.
    timeout_sec : float | None
        Request timeout in seconds. `None` = use SDK/provider default.

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
    # Step 2-3: Dedupe cache check
    # -------------------------------------------------------------------------
    # Import dedupe functions (only when cache is enabled to avoid circular import)
    dedupe_key: str | None = None
    if dedupe_cache is not None:
        dedupe_key = compute_dedupe_key(
            operation="upsert",
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            value=norm_value,
            ttl=norm_ttl,
            comment=norm_comment,
            proxied=proxied,
        )

        cached = await dedupe_cache.get(dedupe_key)
        if cached is not None:
            logger.debug(
                "[service: upsert] Dedupe hit: %s...",
                dedupe_key[:16],
            )
            # Build response from cache
            resp_dict = build_deduped_response(cached, dedupe_cache.window_seconds)
            return DDNSResponse(
                status=resp_dict["status"],
                action=resp_dict["action"],
                upstream_called=resp_dict["upstream_called"],
                provider=resp_dict["provider"],
                record=RecordInfo(**resp_dict["record"]),
                result=ResultInfo(
                    effective=EffectiveValues(**resp_dict["result"]["effective"]),
                    upstream=UpstreamInfo(**resp_dict["result"]["upstream"])
                    if resp_dict["result"] and resp_dict["result"].get("upstream")
                    else None,
                    previous_value=resp_dict["result"].get("previous_value")
                    if resp_dict["result"]
                    else None,
                )
                if resp_dict["result"]
                else None,
                warnings=resp_dict["warnings"],
                errors=resp_dict["errors"],
                meta=ResponseMeta(
                    dedupe=DedupeInfo(
                        hit=True,
                        window_sec=dedupe_cache.window_seconds,
                    ),
                ),
                debug=None,
            )

    # -------------------------------------------------------------------------
    # Step 3.5: Singleflight - Become leader or wait for result
    # -------------------------------------------------------------------------
    is_leader = False
    if dedupe_cache is not None and dedupe_config is not None and dedupe_key:
        # Try to become leader (mark as in-flight)
        is_leader = await dedupe_cache.mark_in_flight(
            dedupe_key,
            lease_sec=dedupe_config.singleflight_lease_sec,
        )

        if not is_leader:
            # Another request is in progress, wait for result
            logger.debug(
                "[service: upsert] Singleflight waiting: %s...",
                dedupe_key[:16],
            )
            sf_result = await dedupe_cache.wait_for_result(
                dedupe_key,
                wait_timeout_sec=dedupe_config.singleflight_wait_timeout_sec,
            )
            if sf_result is not None and sf_result.base is not None:
                # Leader completed, use their result
                resp_dict = build_deduped_response(
                    sf_result, dedupe_cache.window_seconds
                )
                return DDNSResponse(
                    status=resp_dict["status"],
                    action=resp_dict["action"],
                    upstream_called=resp_dict["upstream_called"],
                    provider=resp_dict["provider"],
                    record=RecordInfo(**resp_dict["record"]),
                    result=ResultInfo(
                        effective=EffectiveValues(**resp_dict["result"]["effective"]),
                        upstream=UpstreamInfo(**resp_dict["result"]["upstream"])
                        if resp_dict["result"] and resp_dict["result"].get("upstream")
                        else None,
                        previous_value=resp_dict["result"].get("previous_value")
                        if resp_dict["result"]
                        else None,
                    )
                    if resp_dict["result"]
                    else None,
                    warnings=resp_dict["warnings"],
                    errors=resp_dict["errors"],
                    meta=ResponseMeta(
                        dedupe=DedupeInfo(
                            hit=True,
                            window_sec=dedupe_cache.window_seconds,
                        ),
                    ),
                    debug=None,
                )

            # Wait timeout - return error (DO NOT retry)
            logger.warning(
                "[service: upsert] Singleflight wait timeout: %s...",
                dedupe_key[:16],
            )
            return _build_error_response(
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record=norm_record,
                error=ErrorModel(
                    code=ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT,
                    message="Another request is in progress, wait timeout exceeded",
                ),
            )

    # -------------------------------------------------------------------------
    # Step 4: Find existing record
    # -------------------------------------------------------------------------
    try:
        existing = await provider_instance.find_record(
            zone=norm_zone,
            record=norm_record,
            record_type=record_type_enum,
            credentials=credentials,
            timeout_sec=timeout_sec,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: upsert] find_record failed: '%s'",
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
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
                timeout_sec=timeout_sec,
            )
        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[service: upsert] create_record failed: '%s'",
                e,
            )
            # Clear singleflight so waiters get notified
            if dedupe_cache is not None and is_leader and dedupe_key:
                await dedupe_cache.clear_in_flight(dedupe_key)
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
            # Clear singleflight so waiters get notified
            if dedupe_cache is not None and is_leader and dedupe_key:
                await dedupe_cache.clear_in_flight(dedupe_key)
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

        # Update dedupe cache
        if dedupe_cache is not None and dedupe_key is not None:
            await dedupe_cache.set(
                dedupe_key,
                create_cached_base(
                    status="success",
                    action="created",
                    provider=provider,
                    zone=norm_zone,
                    record_type=record_type_enum.value,
                    record=norm_record,
                    record_id=result.record_id,
                    zone_id=result.zone_id,
                    value=norm_value,
                    ttl=norm_ttl,
                    comment=norm_comment,
                    proxied=proxied,
                    previous_value=None,
                    warnings=result.warnings or [],
                ),
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
        # No change needed - still cache this result
        if dedupe_cache is not None and dedupe_key is not None:
            await dedupe_cache.set(
                dedupe_key,
                create_cached_base(
                    status="success",
                    action="unchanged",
                    provider=provider,
                    zone=norm_zone,
                    record_type=record_type_enum.value,
                    record=norm_record,
                    record_id=existing.record_id,
                    zone_id=existing.zone_id,
                    value=existing_value,
                    ttl=existing.ttl,
                    comment=existing.comment,
                    proxied=existing.proxied,
                    previous_value=None,
                    warnings=[],
                ),
            )

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
            timeout_sec=timeout_sec,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: upsert] update_record failed: '%s'",
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
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
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
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

    # Compute effective values for cache
    eff_ttl = norm_ttl if norm_ttl is not None else existing.ttl
    eff_comment = norm_comment if norm_comment is not None else existing.comment
    eff_proxied = proxied if proxied is not None else existing.proxied
    eff_record_id = result.record_id or existing.record_id
    eff_zone_id = result.zone_id or existing.zone_id

    # Update dedupe cache
    if dedupe_cache is not None and dedupe_key is not None:
        await dedupe_cache.set(
            dedupe_key,
            create_cached_base(
                status="success",
                action="updated",
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record=norm_record,
                record_id=eff_record_id,
                zone_id=eff_zone_id,
                value=norm_value,
                ttl=eff_ttl,
                comment=eff_comment,
                proxied=eff_proxied,
                previous_value=existing_value if value_changed else None,
                warnings=result.warnings or [],
            ),
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
            ttl=eff_ttl,
            comment=eff_comment,
            proxied=eff_proxied,
        ),
        upstream=UpstreamInfo(
            record_id=eff_record_id,
            zone_id=eff_zone_id,
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
    *,
    dedupe_cache: DedupeCache | None = None,
    dedupe_config: DedupeConfig | None = None,
    timeout_sec: float | None = None,
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
    dedupe_cache : DedupeCache | None
        Optional dedupe cache for request deduplication.
    timeout_sec : float | None
        Request timeout in seconds. `None` = use SDK/provider default.

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
    # Step 2-3: Dedupe cache check
    # -------------------------------------------------------------------------
    dedupe_key: str | None = None
    if dedupe_cache is not None:
        dedupe_key = compute_dedupe_key(
            operation="delete",
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record=norm_record,
            value=None,  # DELETE: no value
            ttl=None,  # DELETE: no ttl
            comment=None,  # DELETE: no comment
            proxied=None,  # DELETE: no proxied
        )

        cached = await dedupe_cache.get(dedupe_key)
        if cached is not None:
            logger.debug(
                "[service: delete] Dedupe hit: %s...",
                dedupe_key[:16],
            )
            resp_dict = build_deduped_response(cached, dedupe_cache.window_seconds)
            return DDNSResponse(
                status=resp_dict["status"],
                action=resp_dict["action"],
                upstream_called=resp_dict["upstream_called"],
                provider=resp_dict["provider"],
                record=RecordInfo(**resp_dict["record"]),
                result=ResultInfo(
                    effective=EffectiveValues(**resp_dict["result"]["effective"]),
                    upstream=UpstreamInfo(**resp_dict["result"]["upstream"])
                    if resp_dict["result"] and resp_dict["result"].get("upstream")
                    else None,
                    previous_value=resp_dict["result"].get("previous_value")
                    if resp_dict["result"]
                    else None,
                )
                if resp_dict["result"]
                else None,
                warnings=resp_dict["warnings"],
                errors=resp_dict["errors"],
                meta=ResponseMeta(
                    dedupe=DedupeInfo(
                        hit=True,
                        window_sec=dedupe_cache.window_seconds,
                    ),
                ),
                debug=None,
            )

    # -------------------------------------------------------------------------
    # Step 3.5: Singleflight - Become leader or wait for result
    # -------------------------------------------------------------------------
    is_leader = False
    if dedupe_cache is not None and dedupe_config is not None and dedupe_key:
        # Try to become leader (mark as in-flight)
        is_leader = await dedupe_cache.mark_in_flight(
            dedupe_key,
            lease_sec=dedupe_config.singleflight_lease_sec,
        )

        if not is_leader:
            # Another request is in progress, wait for result
            logger.debug(
                "[service: delete] Singleflight waiting: %s...",
                dedupe_key[:16],
            )
            sf_result = await dedupe_cache.wait_for_result(
                dedupe_key,
                wait_timeout_sec=dedupe_config.singleflight_wait_timeout_sec,
            )
            if sf_result is not None and sf_result.base is not None:
                # Leader completed, use their result
                resp_dict = build_deduped_response(
                    sf_result, dedupe_cache.window_seconds
                )
                return DDNSResponse(
                    status=resp_dict["status"],
                    action=resp_dict["action"],
                    upstream_called=resp_dict["upstream_called"],
                    provider=resp_dict["provider"],
                    record=RecordInfo(**resp_dict["record"]),
                    result=ResultInfo(
                        effective=EffectiveValues(**resp_dict["result"]["effective"]),
                        upstream=UpstreamInfo(**resp_dict["result"]["upstream"])
                        if resp_dict["result"] and resp_dict["result"].get("upstream")
                        else None,
                        previous_value=resp_dict["result"].get("previous_value")
                        if resp_dict["result"]
                        else None,
                    )
                    if resp_dict["result"]
                    else None,
                    warnings=resp_dict["warnings"],
                    errors=resp_dict["errors"],
                    meta=ResponseMeta(
                        dedupe=DedupeInfo(
                            hit=True,
                            window_sec=dedupe_cache.window_seconds,
                        ),
                    ),
                    debug=None,
                )

            # Wait timeout - return error (DO NOT retry)
            logger.warning(
                "[service: delete] Singleflight wait timeout: %s...",
                dedupe_key[:16],
            )
            return _build_error_response(
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record=norm_record,
                error=ErrorModel(
                    code=ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT,
                    message="Another request is in progress, wait timeout exceeded",
                ),
            )

    # -------------------------------------------------------------------------
    # Step 4: Find existing record
    # -------------------------------------------------------------------------
    try:
        existing = await provider_instance.find_record(
            zone=norm_zone,
            record=norm_record,
            record_type=record_type_enum,
            credentials=credentials,
            timeout_sec=timeout_sec,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: delete] find_record failed: '%s'",
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
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
            timeout_sec=timeout_sec,
        )
    except Exception as e:  # noqa: BLE001
        logger.error(  # noqa: TRY400
            "[service: delete] delete_record failed: '%s'",
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
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
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
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

    # Update dedupe cache
    if dedupe_cache is not None and dedupe_key is not None:
        await dedupe_cache.set(
            dedupe_key,
            create_cached_base(
                status="success",
                action="deleted",
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record=norm_record,
                record_id=result.record_id or existing.record_id,
                zone_id=result.zone_id or existing.zone_id,
                value=existing.value,  # Store deleted value for reference
                ttl=existing.ttl,
                comment=existing.comment,
                proxied=existing.proxied,
                previous_value=None,
                warnings=result.warnings or [],
            ),
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
