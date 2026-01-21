"""
Service layer for DDNS Gateway.

This module provides the core business logic for DNS record operations,
orchestrating the flow between normalization, provider calls, and response
building.

Debug Information
-----------------
When ``include_debug_info=True``, the service layer collects raw input
parameters and their normalized forms, returning them in the response's
``debug`` field. This is controlled by the ``response.include_debug_info``
configuration option and is disabled by default for security reasons.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ddns_gateway.dedupe import (
    build_dedupe_response_dict,
    compute_dedupe_key,
    create_cached_base,
)
from ddns_gateway.models import (
    DDNSResponse,
    DNSProvider,
    EffectiveValues,
    ErrorCode,
    ErrorModel,
    RecordType,
    ResponseMeta,
    SingleflightInfo,
    UpstreamInfo,
    WarningCode,
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


def _build_debug_payload(
    *,
    zone: str,
    record: str,
    record_type: str,
    value: str | None = None,
    ttl: int | None = None,
    comment: str | None = None,
    proxied: bool | None = None,
) -> dict[str, Any]:
    """
    Build a payload dictionary for debug info (raw_input or normalized).

    Only includes optional fields if they are not None.

    Parameters
    ----------
    zone : str
        The zone value.
    record : str
        The record value.
    record_type : str
        The record type value.
    value : str | None
        The record value (for upsert operations).
    ttl : int | None
        The TTL value.
    comment : str | None
        The comment value.
    proxied : bool | None
        The proxied value (Cloudflare only, A/AAAA/CNAME).

    Returns
    -------
    dict[str, Any]
        The debug dictionary with non-None fields.
    """
    result: dict[str, Any] = {
        "zone": zone,
        "record": record,
        "type": record_type,
    }
    if value is not None:
        result["value"] = value
    if ttl is not None:
        result["ttl"] = ttl
    if comment is not None:
        result["comment"] = comment
    if proxied is not None:
        result["proxied"] = proxied
    return result


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
    include_debug_info: bool = False,
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
       else return unchanged
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
    dedupe_config : DedupeConfig | None
        Optional dedupe configuration for singleflight settings.
    timeout_sec : float | None
        Request timeout in seconds. `None` = use SDK/provider default.
    include_debug_info : bool
        Whether to include debug information (raw input, normalized) in response.
        Controlled by ``response.include_debug_info`` config option.

    Returns
    -------
    DDNSResponse
        The operation response.
    """
    warnings: list[WarningModel] = []

    # Build raw input for debug (before normalization)
    raw_input = _build_debug_payload(
        zone=zone,
        record=record,
        record_type=record_type,
        value=value,
        ttl=ttl,
        comment=comment,
        proxied=proxied,
    )

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
            logger.debug(
                '[upsert] Invalid record type: "%s" (Provider: "%s", Zone: "%s", Record: "%s").',
                record_type,
                provider,
                zone,
                record,
            )
            return DDNSResponse.error(
                provider=provider,
                zone=zone,
                record_type=record_type,
                record_name=record,
                errors=ErrorModel(
                    code=ErrorCode.INVALID_RECORD_TYPE,
                    message=f"Invalid record type: {record_type}",
                    field="type",
                ),
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=None,
            )

        norm_value = normalize_value(value, record_type_enum.value)
        norm_ttl = normalize_ttl(ttl)
        norm_comment = normalize_comment(comment)

    except NormalizeError as e:
        logger.debug(
            '[upsert] Normalize failed. Code: "%s", Field: "%s", Message: "%s" ',
            '(Provider: "%s", Zone: "%s", Record: "%s", Type: "%s").',
            e.code,
            e.field,
            e.message,
            provider,
            zone,
            record,
            record_type,
        )
        return DDNSResponse.error(
            provider=provider,
            zone=zone,
            record_type=record_type,
            record_name=record,
            errors=ErrorModel(
                code=e.code,
                message=e.message,
                field=e.field,
            ),
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=None,
        )

    # Validate 'proxied': only effective for Cloudflare A/AAAA/CNAME records.
    # For other cases, set to None and emit a warning.
    proxied_validated = proxied
    if proxied is not None:
        if provider != DNSProvider.CLOUDFLARE:
            warnings.append(
                WarningModel(
                    code=WarningCode.PROXIED_IGNORED_FOR_NON_CF,
                    message="Proxied parameter ignored for non-Cloudflare provider",
                    field="proxied",
                    details={"provider": provider},
                ),
            )
            proxied_validated = None
        elif record_type_enum not in {RecordType.A, RecordType.AAAA, RecordType.CNAME}:
            warnings.append(
                WarningModel(
                    code=WarningCode.PROXIED_IGNORED,
                    message=(
                        "The 'proxied' parameter is only supported for A/AAAA/CNAME records "
                        "and is ignored for the current record type."
                    ),
                    field="proxied",
                    details={"record_type": record_type_enum.value},
                ),
            )
            proxied_validated = None

    # Build normalized for debug (after successful normalization)
    normalized = _build_debug_payload(
        zone=norm_zone,
        record=norm_record,
        record_type=record_type_enum.value,
        value=norm_value,
        ttl=norm_ttl,
        comment=norm_comment,
        proxied=proxied_validated,
    )

    # -------------------------------------------------------------------------
    # Step 2-3: Dedupe cache check
    # -------------------------------------------------------------------------
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
            proxied=proxied_validated,
        )

        cached = await dedupe_cache.get(dedupe_key)
        if cached is not None:
            logger.debug(
                '[upsert] Dedupe hit: "%s" ...',
                dedupe_key[:16],
            )
            # Build response from cache
            resp_dict = build_dedupe_response_dict(cached, dedupe_cache.window_seconds)
            return DDNSResponse.from_dedupe_dict(
                resp_dict,
                dedupe_cache.window_seconds,
                extra_warnings=warnings,
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=normalized,
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
                '[upsert] Singleflight waiting: "%s" ...',
                dedupe_key[:16],
            )
            sf_result = await dedupe_cache.wait_for_result(
                dedupe_key,
                wait_timeout_sec=dedupe_config.singleflight_wait_timeout_sec,
            )
            if sf_result is not None and sf_result.base is not None:
                # Leader completed, use their result
                resp_dict = build_dedupe_response_dict(
                    sf_result,
                    dedupe_cache.window_seconds,
                )
                return DDNSResponse.from_dedupe_dict(
                    resp_dict,
                    dedupe_cache.window_seconds,
                    extra_warnings=warnings,
                    include_debug_info=include_debug_info,
                    raw_input=raw_input,
                    normalized=normalized,
                )

            # Wait timeout - return error (DO NOT retry)
            logger.warning(
                '[upsert] Singleflight wait timeout: "%s" ...',
                dedupe_key[:16],
            )

            # Calculate in_flight_age_sec for singleflight info
            in_flight_age = await dedupe_cache.get_in_flight_age(dedupe_key)

            # Edge case: Leader may have completed during the race window
            # between wait_for_result() timeout and get_in_flight_age() call
            if in_flight_age is None:
                # Try to get the result one more time
                cached = await dedupe_cache.get(dedupe_key)
                if cached is not None:
                    # Leader completed! Return success instead of timeout error
                    logger.debug(
                        '[upsert] Singleflight race: leader completed during timeout handling: "%s" ...',
                        dedupe_key[:16],
                    )
                    resp_dict = build_dedupe_response_dict(
                        cached,
                        dedupe_cache.window_seconds,
                    )
                    return DDNSResponse.from_dedupe_dict(
                        resp_dict,
                        dedupe_cache.window_seconds,
                        extra_warnings=warnings,
                        include_debug_info=include_debug_info,
                        raw_input=raw_input,
                        normalized=normalized,
                    )
                # Still no result - Leader may have failed and cleared in-flight
                # Use wait_timeout as conservative lower bound estimate
                in_flight_age = dedupe_config.singleflight_wait_timeout_sec

            # Calculate retry_after_sec (remaining lease time, minimum 0)
            retry_after = max(
                0.0,
                dedupe_config.singleflight_lease_sec - in_flight_age,
            )

            return DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT,
                    message="Another request is in progress, wait timeout exceeded",
                ),
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record_name=norm_record,
                warnings=warnings,
                meta=ResponseMeta(
                    singleflight=SingleflightInfo(
                        in_flight=True,
                        in_flight_age_sec=in_flight_age,
                        retry_after_sec=retry_after,
                    ),
                ),
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=normalized,
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
            '[upsert] Failed to query existing record: "%s".',
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
        return DDNSResponse.error(
            errors=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to query existing record: {e}",
            ),
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            upstream_called=True,
            warnings=warnings,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
        )

    # Build desired state
    desired = DesiredState(
        value=norm_value,
        ttl=norm_ttl,
        comment=norm_comment,
        proxied=proxied_validated,
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
                '[upsert] Failed to create record: "%s".',
                e,
            )
            # Clear singleflight so waiters get notified
            if dedupe_cache is not None and is_leader and dedupe_key:
                await dedupe_cache.clear_in_flight(dedupe_key)
            return DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.UPSTREAM_API_ERROR,
                    message=f"Failed to create record: {e}",
                ),
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record_name=norm_record,
                upstream_called=True,
                warnings=warnings,
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=normalized,
            )

        if not result.success:
            # Clear singleflight so waiters get notified
            if dedupe_cache is not None and is_leader and dedupe_key:
                await dedupe_cache.clear_in_flight(dedupe_key)
            return DDNSResponse.error(
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record_name=norm_record,
                errors=ErrorModel(
                    code=ErrorCode.UPSTREAM_API_ERROR,
                    message=result.message,
                ),
                upstream_called=True,
                warnings=warnings + (result.warnings or []),
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=normalized,
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
                    proxied=proxied_validated,
                    previous_value=None,
                    warnings=warnings + (result.warnings or []),
                ),
            )

        combined_warnings = warnings + (result.warnings or [])
        return DDNSResponse.success(
            action="created",
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            upstream_called=True,
            effective=EffectiveValues(
                value=norm_value,
                ttl=norm_ttl,
                comment=norm_comment,
                proxied=proxied_validated,
            ),
            upstream=UpstreamInfo(
                record_id=result.record_id,
                zone_id=result.zone_id,
                raw_status=result.raw_status,
                http_status=result.http_status,
            ),
            warnings=combined_warnings,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
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
    proxied_changed = (
        proxied_validated is not None and existing.proxied != proxied_validated
    )

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
                    warnings=warnings,
                ),
            )

        return DDNSResponse.success(
            action="unchanged",
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            upstream_called=True,
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
            warnings=warnings,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
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
            '[upsert] Failed to update record: "%s".',
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
        return DDNSResponse.error(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            errors=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to update record: {e}",
            ),
            upstream_called=True,
            warnings=warnings,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
        )

    if not result.success:
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
        return DDNSResponse.error(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            errors=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=result.message,
            ),
            upstream_called=True,
            warnings=warnings + (result.warnings or []),
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
        )

    # Compute effective values for cache
    eff_ttl = norm_ttl if norm_ttl is not None else existing.ttl
    eff_comment = norm_comment if norm_comment is not None else existing.comment
    eff_proxied = (
        proxied_validated if proxied_validated is not None else existing.proxied
    )
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
                warnings=warnings + (result.warnings or []),
            ),
        )

    combined_warnings = warnings + (result.warnings or [])
    return DDNSResponse.success(
        action="updated",
        provider=provider,
        zone=norm_zone,
        record_type=record_type_enum.value,
        record_name=norm_record,
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
        warnings=combined_warnings,
        include_debug_info=include_debug_info,
        raw_input=raw_input,
        normalized=normalized,
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
    include_debug_info: bool = False,
) -> DDNSResponse:
    """
    Delete a DNS record.

    Flow:
    1. Normalize inputs
    2. [Reserved] Compute dedupe key (value/ttl/comment/proxied = None)
    3. [Reserved] Check dedupe cache -> short-circuit if hit
    4. Call provider.find_record()
    5. If not found: return unchanged (success)
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
    dedupe_config : DedupeConfig | None
        Optional dedupe configuration for singleflight settings.
    timeout_sec : float | None
        Request timeout in seconds. `None` = use SDK/provider default.
    include_debug_info : bool
        Whether to include debug information (raw input, normalized) in response.
        Controlled by ``response.include_debug_info`` config option.

    Returns
    -------
    DDNSResponse
        The operation response.
    """
    warnings: list[WarningModel] = []
    # Build raw input for debug (before normalization)
    raw_input = _build_debug_payload(
        zone=zone,
        record=record,
        record_type=record_type,
    )

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
            logger.debug(
                '[delete] Invalid record type: "%s" (Provider: "%s", Zone: "%s", Record: "%s").',
                record_type,
                provider,
                zone,
                record,
            )
            return DDNSResponse.error(
                provider=provider,
                zone=zone,
                record_type=record_type,
                record_name=record,
                errors=ErrorModel(
                    code=ErrorCode.INVALID_RECORD_TYPE,
                    message=f"Invalid record type: {record_type}",
                    field="type",
                ),
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=None,
            )

    except NormalizeError as e:
        logger.debug(
            '[delete] Normalize failed. Code: "%s", Field: "%s", Message: "%s" '
            '(Provider: "%s", Zone: "%s", Record: "%s", Type: "%s").',
            e.code,
            e.field,
            e.message,
            provider,
            zone,
            record,
            record_type,
        )
        return DDNSResponse.error(
            provider=provider,
            zone=zone,
            record_type=record_type,
            record_name=record,
            errors=ErrorModel(
                code=e.code,
                message=e.message,
                field=e.field,
            ),
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=None,
        )

    # Build normalized for debug (after successful normalization)
    normalized = _build_debug_payload(
        zone=norm_zone,
        record=norm_record,
        record_type=record_type_enum.value,
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
                '[delete] Dedupe hit: "%s" ...',
                dedupe_key[:16],
            )
            resp_dict = build_dedupe_response_dict(cached, dedupe_cache.window_seconds)
            return DDNSResponse.from_dedupe_dict(
                resp_dict,
                dedupe_cache.window_seconds,
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=normalized,
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
                '[delete] Singleflight waiting: "%s" ...',
                dedupe_key[:16],
            )
            sf_result = await dedupe_cache.wait_for_result(
                dedupe_key,
                wait_timeout_sec=dedupe_config.singleflight_wait_timeout_sec,
            )
            if sf_result is not None and sf_result.base is not None:
                # Leader completed, use their result
                resp_dict = build_dedupe_response_dict(
                    sf_result,
                    dedupe_cache.window_seconds,
                )
                return DDNSResponse.from_dedupe_dict(
                    resp_dict,
                    dedupe_cache.window_seconds,
                    include_debug_info=include_debug_info,
                    raw_input=raw_input,
                    normalized=normalized,
                )

            # Wait timeout - return error (DO NOT retry)
            logger.warning(
                '[delete] Singleflight wait timeout: "%s" ...',
                dedupe_key[:16],
            )

            # Calculate in_flight_age_sec for singleflight info
            in_flight_age = await dedupe_cache.get_in_flight_age(dedupe_key)

            # Edge case: Leader may have completed during the race window
            # between wait_for_result() timeout and get_in_flight_age() call
            if in_flight_age is None:
                # Try to get the result one more time
                cached = await dedupe_cache.get(dedupe_key)
                if cached is not None:
                    # Leader completed! Return success instead of timeout error
                    logger.debug(
                        '[delete] Singleflight race: leader completed during timeout handling: "%s" ...',
                        dedupe_key[:16],
                    )
                    resp_dict = build_dedupe_response_dict(
                        cached,
                        dedupe_cache.window_seconds,
                    )
                    return DDNSResponse.from_dedupe_dict(
                        resp_dict,
                        dedupe_cache.window_seconds,
                        include_debug_info=include_debug_info,
                        raw_input=raw_input,
                        normalized=normalized,
                    )
                # Still no result - Leader may have failed and cleared in-flight
                # Use wait_timeout as conservative lower bound estimate
                in_flight_age = dedupe_config.singleflight_wait_timeout_sec

            # Calculate retry_after_sec (remaining lease time, minimum 0)
            retry_after = max(
                0.0,
                dedupe_config.singleflight_lease_sec - in_flight_age,
            )

            return DDNSResponse.error(
                provider=provider,
                zone=norm_zone,
                record_type=record_type_enum.value,
                record_name=norm_record,
                errors=ErrorModel(
                    code=ErrorCode.SINGLEFLIGHT_WAIT_TIMEOUT,
                    message="Another request is in progress, wait timeout exceeded",
                ),
                meta=ResponseMeta(
                    singleflight=SingleflightInfo(
                        in_flight=True,
                        in_flight_age_sec=in_flight_age,
                        retry_after_sec=retry_after,
                    ),
                ),
                include_debug_info=include_debug_info,
                raw_input=raw_input,
                normalized=normalized,
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
            '[delete] Failed to query existing record: "%s".',
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
        return DDNSResponse.error(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            errors=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to query existing record: {e}",
            ),
            upstream_called=True,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
        )

    # -------------------------------------------------------------------------
    # Step 5: Return unchanged if not found
    # -------------------------------------------------------------------------
    if existing is None:
        warnings.append(
            WarningModel(
                code=WarningCode.RECORD_NOT_FOUND,
                message="Record not found, nothing to delete",
                field="record",
            ),
        )
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
                    record_id=None,
                    zone_id=None,
                    value="",
                    ttl=None,
                    comment=None,
                    proxied=None,
                    previous_value=None,
                    warnings=warnings,
                ),
            )
        return DDNSResponse.success(
            action="unchanged",
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            upstream_called=True,
            warnings=warnings,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
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
            '[delete] Failed to delete record: "%s".',
            e,
        )
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
        return DDNSResponse.error(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            errors=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=f"Failed to delete record: {e}",
            ),
            upstream_called=True,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
        )

    if not result.success:
        # Clear singleflight so waiters get notified
        if dedupe_cache is not None and is_leader and dedupe_key:
            await dedupe_cache.clear_in_flight(dedupe_key)
        return DDNSResponse.error(
            provider=provider,
            zone=norm_zone,
            record_type=record_type_enum.value,
            record_name=norm_record,
            errors=ErrorModel(
                code=ErrorCode.UPSTREAM_API_ERROR,
                message=result.message,
            ),
            upstream_called=True,
            warnings=result.warnings,
            include_debug_info=include_debug_info,
            raw_input=raw_input,
            normalized=normalized,
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

    return DDNSResponse.success(
        action="deleted",
        provider=provider,
        zone=norm_zone,
        record_type=record_type_enum.value,
        record_name=norm_record,
        upstream_called=True,
        upstream=UpstreamInfo(
            record_id=result.record_id or existing.record_id,
            zone_id=result.zone_id or existing.zone_id,
            raw_status=result.raw_status,
            http_status=result.http_status,
        ),
        warnings=result.warnings,
        include_debug_info=include_debug_info,
        raw_input=raw_input,
        normalized=normalized,
    )
