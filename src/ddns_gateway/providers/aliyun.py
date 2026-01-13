"""
Alibaba Cloud DNS (alidns) provider implementation.

This module implements the Alibaba Cloud DNS API using the official SDK.
Endpoint: alidns.aliyuncs.com (unified for domestic and international).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from alibabacloud_alidns20150109 import models as alidns_models
from alibabacloud_alidns20150109.client import Client as AlidnsClient
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_tea_util import models as util_models

from ddns_gateway.models import RecordType, WarningCode, WarningModel
from ddns_gateway.normalize import comments_equal, normalize_upstream_value
from ddns_gateway.providers.base import BaseDNSProvider, ProviderError, ProviderResult
from ddns_gateway.types import DesiredState, ExistingRecord, UpstreamResult

if TYPE_CHECKING:
    from typing import Any, Final


# Alibaba Cloud DNS endpoint (unified)
ALIDNS_ENDPOINT: Final[str] = "alidns.aliyuncs.com"


logger = logging.getLogger(__name__)


class AliyunProvider(BaseDNSProvider):
    """
    Alibaba Cloud DNS (alidns) provider.

    Uses the official alibabacloud_alidns20150109 SDK.
    Supports record remarks via a separate API call.
    """

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "aliyun"

    def _create_client(
        self,
        access_key_id: str,
        access_key_secret: str,
    ) -> AlidnsClient:
        """
        Create an Alibaba Cloud DNS client.

        Parameters
        ----------
        access_key_id : str
            Alibaba Cloud Access Key ID.
        access_key_secret : str
            Alibaba Cloud Access Key Secret.

        Returns
        -------
        AlidnsClient
            The DNS client instance.
        """
        config = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            endpoint=ALIDNS_ENDPOINT,
        )
        return AlidnsClient(config)

    # =========================================================================
    # New Interface (Phase 2 Refactoring) - Stub Implementations
    # =========================================================================

    async def find_record(
        self,
        zone: str,
        record: str,
        record_type: RecordType,
        credentials: dict[str, str],
    ) -> ExistingRecord | None:
        """
        Find an existing DNS record.

        Parameters
        ----------
        zone : str
            The DNS zone (normalized).
        record : str
            The host record name (normalized).
        record_type : RecordType
            The record type.
        credentials : dict[str, str]
            Must contain "id" and "secret".

        Returns
        -------
        ExistingRecord | None
            The existing record if found, None otherwise.

        Raises
        ------
        ProviderError
            If multiple records are found or API error occurs.
        """
        access_key_id = credentials.get("id")
        access_key_secret = credentials.get("secret")

        if not access_key_id or not access_key_secret:
            msg = "Missing required credentials: id and secret"
            raise ProviderError(msg)

        client = self._create_client(access_key_id, access_key_secret)
        runtime = util_models.RuntimeOptions()

        records = await self._describe_records(
            client,
            runtime,
            zone,
            record,
            record_type,
        )

        if records is None:
            msg = "Failed to query DNS records from Aliyun API"
            raise ProviderError(msg)

        if len(records) == 0:
            return None

        if len(records) > 1:
            msg = f"Multiple records found for {record}.{zone} ({record_type.value}), manual resolution required"
            raise ProviderError(msg)

        raw = records[0]
        return ExistingRecord(
            record_id=str(raw.get("record_id", "")),
            zone_id=None,  # Aliyun does not use zone_id
            value=normalize_upstream_value(
                str(raw.get("value", "")),
                record_type.value,
            ),
            ttl=int(raw.get("ttl", 0)),
            comment=raw.get("remark"),
            proxied=None,  # Not supported by Aliyun
            raw=raw,
        )

    async def create_record(
        self,
        zone: str,
        record: str,
        record_type: RecordType,
        desired: DesiredState,
        credentials: dict[str, str],
    ) -> UpstreamResult:
        """
        Create a new DNS record.

        Parameters
        ----------
        zone : str
            The DNS zone (normalized).
        record : str
            The host record name (normalized).
        record_type : RecordType
            The record type.
        desired : DesiredState
            The desired state for the record.
        credentials : dict[str, str]
            Must contain "id" and "secret".

        Returns
        -------
        UpstreamResult
            The result of the create operation.
        """
        access_key_id = credentials.get("id")
        access_key_secret = credentials.get("secret")

        if not access_key_id or not access_key_secret:
            return UpstreamResult(
                success=False,
                action="created",
                message="Missing required credentials: id and secret",
            )

        client = self._create_client(access_key_id, access_key_secret)
        runtime = util_models.RuntimeOptions()

        # Delegate to legacy _add_record helper
        result = await self._add_record(
            client,
            runtime,
            zone,
            record,
            record_type,
            desired.value,
            desired.ttl,
            desired.comment,
        )

        # Convert ProviderResult to UpstreamResult
        return UpstreamResult(
            success=result.success,
            action=result.action or "created",
            message=result.message,
            record_id=result.record_id,
            zone_id=None,
            extra={"request_id": result.request_id} if result.request_id else None,
            warnings=result.warnings,
        )

    async def update_record_v2(
        self,
        zone: str,
        existing: ExistingRecord,
        desired: DesiredState,
        credentials: dict[str, str],
    ) -> UpstreamResult:
        """
        Update an existing DNS record.

        Parameters
        ----------
        zone : str
            The DNS zone (normalized). Unused in this implementation.

            This argument is kept to satisfy the BaseDNSProvider interface,
            but Aliyun uses the record_id from the existing record instead.
        existing : ExistingRecord
            The existing record to update.
        desired : DesiredState
            The desired state for the record.
        credentials : dict[str, str]
            Must contain "id" and "secret".

        Returns
        -------
        UpstreamResult
            The result of the update operation.
        """
        _ = zone  # Unused, as we use record_id from ExistingRecord
        access_key_id = credentials.get("id")
        access_key_secret = credentials.get("secret")

        if not access_key_id or not access_key_secret:
            return UpstreamResult(
                success=False,
                action="updated",
                message="Missing required credentials: id and secret",
            )

        client = self._create_client(access_key_id, access_key_secret)
        runtime = util_models.RuntimeOptions()

        # Get record type from raw data
        record_type = existing.raw.get("type", "")

        # Normalize desired value for comparison
        desired_value_normalized = normalize_upstream_value(desired.value, record_type)

        # Check if update is needed
        value_changed = existing.value != desired_value_normalized
        ttl_changed = desired.ttl is not None and existing.ttl != desired.ttl
        comment_changed = desired.comment is not None and not comments_equal(
            existing.comment,
            desired.comment,
        )

        if not value_changed and not ttl_changed and not comment_changed:
            return UpstreamResult(
                success=True,
                action="nochange",
                message=f"DNS record unchanged for {existing.raw.get('rr', '')}",
                record_id=existing.record_id,
                zone_id=None,
            )

        warnings: list[WarningModel] = []
        request_id: str | None = None

        # Update record if value or ttl changed
        if value_changed or ttl_changed:
            try:
                request = alidns_models.UpdateDomainRecordRequest(
                    record_id=existing.record_id,
                    rr=existing.raw.get("rr", ""),
                    type=record_type,
                    value=desired.value,
                )
                if desired.ttl is not None:
                    request.ttl = desired.ttl
                response = await client.update_domain_record_with_options_async(
                    request,
                    runtime,
                )
                request_id = response.body.request_id

                logger.debug("[aliyun] UpdateDomainRecord -> RequestId: %s", request_id)
                logger.debug("[aliyun] Response: %s", response.body.to_map())

            except Exception as e:  # noqa: BLE001
                logger.error(  # noqa: TRY400
                    "[aliyun: UpdateDomainRecord] Failed to update: '%s'",
                    e,
                )
                return UpstreamResult(
                    success=False,
                    action="updated",
                    message=f"Failed to update record: {e}",
                )

        # Update remark if changed (separate API call)
        if comment_changed and desired.comment is not None:
            remark_result = await self._update_record_remark(
                client,
                runtime,
                existing.record_id,
                desired.comment,
            )
            if not remark_result:
                warnings.append(
                    WarningModel(
                        code=WarningCode.ALI_COMMENT_UPDATE_FAILED,
                        message="Record updated but failed to update remark",
                    ),
                )

        return UpstreamResult(
            success=True,
            action="updated",
            message=f"DNS record updated for {existing.raw.get('rr', '')}",
            record_id=existing.record_id,
            zone_id=None,
            previous_value=existing.value if value_changed else None,
            extra={"request_id": request_id} if request_id else None,
            warnings=warnings if warnings else None,
        )

    async def delete_record(
        self,
        zone: str,
        existing: ExistingRecord,
        credentials: dict[str, str],
    ) -> UpstreamResult:
        """
        Delete an existing DNS record.

        Parameters
        ----------
        zone : str
            The DNS zone (normalized). Unused in this implementation.

            This argument is kept to satisfy the BaseDNSProvider interface,
            but Aliyun uses the record_id from the existing record instead.
        existing : ExistingRecord
            The existing record to delete.
        credentials : dict[str, str]
            Must contain "id" and "secret".

        Returns
        -------
        UpstreamResult
            The result of the delete operation.
        """
        _ = zone  # Unused, as we use record_id from ExistingRecord
        access_key_id = credentials.get("id")
        access_key_secret = credentials.get("secret")

        if not access_key_id or not access_key_secret:
            return UpstreamResult(
                success=False,
                action="deleted",
                message="Missing required credentials: id and secret",
            )

        client = self._create_client(access_key_id, access_key_secret)
        runtime = util_models.RuntimeOptions()

        try:
            request = alidns_models.DeleteDomainRecordRequest(
                record_id=existing.record_id,
            )
            response = await client.delete_domain_record_with_options_async(
                request,
                runtime,
            )
            request_id = response.body.request_id

            logger.debug("[aliyun] DeleteDomainRecord -> RequestId: %s", request_id)
            logger.debug("[aliyun] Response: %s", response.body.to_map())

            return UpstreamResult(
                success=True,
                action="deleted",
                message=f"DNS record deleted for {existing.raw.get('rr', '')}",
                record_id=existing.record_id,
                zone_id=None,
                extra={"request_id": request_id} if request_id else None,
            )

        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[aliyun: DeleteDomainRecord] Failed to delete: '%s'",
                e,
            )
            return UpstreamResult(
                success=False,
                action="deleted",
                message=f"Failed to delete record: {e}",
            )

    # =========================================================================
    # Legacy Interface
    # =========================================================================

    async def update_record(
        self,
        zone: str,
        record: str,
        record_type: RecordType,
        value: str,
        ttl: int | None,
        credentials: dict[str, str],
        comment: str | None = None,
    ) -> ProviderResult:
        """
        Update or create a DNS record in Alibaba Cloud DNS.

        Parameters
        ----------
        zone : str
            The DNS zone (root domain name).
        record : str
            The host record name (use "@" for root).
        record_type : RecordType
            The record type (A, AAAA, CNAME, TXT).
        value : str
            The record value to set.
        ttl : int | None
            Time to live in seconds, or None to use provider default.
        credentials : dict[str, str]
            Must contain "ali_access_key_id" and "ali_access_key_secret".
        comment : str | None, optional
            Optional remark for the record.

        Returns
        -------
        ProviderResult
            The result of the operation.
        """
        access_key_id = credentials.get("ali_access_key_id")
        access_key_secret = credentials.get("ali_access_key_secret")

        if not access_key_id or not access_key_secret:
            return ProviderResult(
                success=False,
                message="Missing required credentials: ali_access_key_id, ali_access_key_secret",
            )

        # Normalize record name for Alibaba Cloud (@ for root, others as-is)
        rr = "@" if record in {"@", ""} else record

        try:
            client = self._create_client(access_key_id, access_key_secret)
            runtime = util_models.RuntimeOptions()

            # Step 1: Query existing records
            records = await self._describe_records(
                client,
                runtime,
                zone,
                rr,
                record_type,
            )

            if records is None:
                return ProviderResult(
                    success=False,
                    message="Failed to query DNS records",
                )

            logger.debug(
                "[aliyun] Found %d records for %s.%s %s",
                len(records),
                rr,
                zone,
                record_type,
            )

            # Step 2: Handle based on number of records found
            if len(records) == 0:
                # Create new record
                return await self._add_record(
                    client,
                    runtime,
                    zone,
                    rr,
                    record_type,
                    value,
                    ttl,
                    comment,
                )
            if len(records) == 1:
                # Update existing record
                return await self._update_or_skip(
                    client,
                    runtime,
                    records[0],
                    value,
                    ttl,
                    comment,
                )
            # Multiple records found - error
            return ProviderResult(
                success=False,
                message=(
                    f"Multiple records ({len(records)}) found for {rr}.{zone} {record_type}. "
                    "Please manually clean up duplicate records."
                ),
            )

        except Exception as e:  # noqa: BLE001
            logger.error("[aliyun] Failed to query/manipulate records: '%s'", e)  # noqa: TRY400
            return ProviderResult(
                success=False,
                message=f"Alibaba Cloud DNS error: {e}",
            )

    async def _describe_records(
        self,
        client: AlidnsClient,
        runtime: util_models.RuntimeOptions,
        zone: str,
        rr: str,
        record_type: RecordType,
    ) -> list[dict[str, Any]] | None:
        """
        Query DNS records.

        Parameters
        ----------
        client : AlidnsClient
            The DNS client.
        runtime : RuntimeOptions
            Runtime options.
        zone : str
            The DNS zone name.
        rr : str
            The host record (record name).
        record_type : RecordType
            The record type.

        Returns
        -------
        list[dict[str, Any]] | None
            List of matching records or None on error.
        """
        try:
            request = alidns_models.DescribeDomainRecordsRequest(
                domain_name=zone,
                rrkey_word=rr,
                type=record_type.value,
            )
            response = await client.describe_domain_records_with_options_async(
                request,
                runtime,
            )
            logger.debug(
                "[aliyun] DescribeDomainRecords -> RequestId: %s",
                response.body.request_id,
            )
            logger.debug("[aliyun] Response: %s", response.body.to_map())

            if response.body.domain_records is None:
                return []

            records = response.body.domain_records.record or []
            # Filter to exact matches (rrkey_word is a keyword search)
            return [
                {
                    "record_id": r.record_id,
                    "rr": r.rr,
                    "value": r.value,
                    "type": r.type,
                    "ttl": r.ttl,
                    "remark": r.remark,
                }
                for r in records
                if r.rr == rr and r.type == record_type.value
            ]

        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[aliyun: DescribeDomainRecords] Failed to describe domain records: '%s'",
                e,
            )
            return None

    async def _add_record(
        self,
        client: AlidnsClient,
        runtime: util_models.RuntimeOptions,
        zone: str,
        rr: str,
        record_type: RecordType,
        value: str,
        ttl: int | None,
        comment: str | None,
    ) -> ProviderResult:
        """
        Add a new DNS record.

        Parameters
        ----------
        client : AlidnsClient
            The DNS client.
        runtime : RuntimeOptions
            Runtime options.
        zone : str
            The DNS zone name.
        rr : str
            The host record.
        record_type : RecordType
            The record type.
        value : str
            The record value.
        ttl : int | None
            Time to live, or None to use provider default.
        comment : str | None
            Optional remark.

        Returns
        -------
        ProviderResult
            The result of the operation.
        """
        try:
            request = alidns_models.AddDomainRecordRequest(
                domain_name=zone,
                rr=rr,
                type=record_type.value,
                value=value,
            )
            if ttl is not None:
                request.ttl = ttl
            response = await client.add_domain_record_with_options_async(
                request,
                runtime,
            )
            record_id = response.body.record_id
            request_id = response.body.request_id

            logger.debug(
                "[aliyun] AddDomainRecord -> RequestId: %s, RecordId: %s",
                request_id,
                record_id,
            )
            logger.debug("[aliyun] Response: %s", response.body.to_map())

            warnings: list[WarningModel] = []

            # Set remark if provided (requires separate API call)
            if comment and record_id:
                remark_result = await self._update_record_remark(
                    client,
                    runtime,
                    record_id,
                    comment,
                )
                if not remark_result:
                    warnings.append(
                        WarningModel(
                            code="comment_partial",
                            message="Record created but failed to set remark",
                        ),
                    )

            return ProviderResult(
                success=True,
                message=f"DNS record created for {rr}.{zone}",
                action="created",
                record_id=record_id,
                request_id=request_id,
                warnings=warnings,
            )

        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[aliyun: AddDomainRecord] Failed to add domain record: '%s'",
                e,
            )
            return ProviderResult(
                success=False,
                message=f"Failed to create record: {e}",
            )

    async def _update_or_skip(
        self,
        client: AlidnsClient,
        runtime: util_models.RuntimeOptions,
        existing: dict[str, Any],
        value: str,
        ttl: int | None,
        comment: str | None,
    ) -> ProviderResult:
        """
        Update an existing record or skip if unchanged.

        Parameters
        ----------
        client : AlidnsClient
            The DNS client.
        runtime : RuntimeOptions
            Runtime options.
        existing : dict[str, Any]
            The existing record data.
        value : str
            The new record value.
        ttl : int
            Time to live.
        comment : str | None
            Optional remark.

        Returns
        -------
        ProviderResult
            The result of the operation.
        """
        record_id = existing["record_id"]
        current_value = existing.get("value", "")
        current_ttl = existing.get("ttl", 0)
        current_remark = existing.get("remark", "")
        rr = existing["rr"]
        record_type = existing["type"]

        # Check if update is needed
        value_changed = current_value != value
        # If ttl / comment None, it implies "keep existing", so we don't treat it as a change.
        # We only flag a change if ttl is explicitly provided (not None) and differs.
        ttl_changed = ttl is not None and current_ttl != ttl
        remark_changed = comment is not None and current_remark != comment

        if not value_changed and not ttl_changed and not remark_changed:
            return ProviderResult(
                success=True,
                message=f"DNS record unchanged for {rr}",
                action="unchanged",
                record_id=record_id,
            )

        warnings: list[WarningModel] = []
        request_id: str | None = None

        # Update record if value changed
        if value_changed:
            try:
                request = alidns_models.UpdateDomainRecordRequest(
                    record_id=record_id,
                    rr=rr,
                    type=record_type,
                    value=value,
                )
                if ttl is not None:
                    request.ttl = ttl
                response = await client.update_domain_record_with_options_async(
                    request,
                    runtime,
                )
                request_id = response.body.request_id

                logger.debug("[aliyun] UpdateDomainRecord -> RequestId: %s", request_id)
                logger.debug("[aliyun] Response: %s", response.body.to_map())

            except Exception as e:  # noqa: BLE001
                logger.error(  # noqa: TRY400
                    "[aliyun: UpdateDomainRecord] Failed to update domain record: '%s'",
                    e,
                )
                return ProviderResult(
                    success=False,
                    message=f"Failed to update record: {e}",
                )

        # Update remark if changed (separate API call)
        if remark_changed and comment is not None:
            remark_result = await self._update_record_remark(
                client,
                runtime,
                record_id,
                comment,
            )
            if not remark_result:
                warnings.append(
                    WarningModel(
                        code="comment_partial",
                        message="Record updated but failed to update remark",
                    ),
                )

        return ProviderResult(
            success=True,
            message=f"DNS record updated for {rr}",
            action="updated",
            record_id=record_id,
            request_id=request_id,
            previous_value=current_value if value_changed else None,
            warnings=warnings,
        )

    async def _update_record_remark(
        self,
        client: AlidnsClient,
        runtime: util_models.RuntimeOptions,
        record_id: str,
        remark: str,
    ) -> bool:
        """
        Update the remark for a record.

        Parameters
        ----------
        client : AlidnsClient
            The DNS client.
        runtime : RuntimeOptions
            Runtime options.
        record_id : str
            The record ID.
        remark : str
            The remark text.

        Returns
        -------
        bool
            True if successful, False otherwise.
        """
        try:
            request = alidns_models.UpdateDomainRecordRemarkRequest(
                record_id=record_id,
                remark=remark,
            )
            response = await client.update_domain_record_remark_with_options_async(
                request,
                runtime,
            )
            logger.debug(
                "[aliyun] UpdateDomainRecordRemark -> RequestId: %s",
                response.body.request_id,
            )
        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[aliyun: UpdateDomainRecordRemark] Failed to update record remark: '%s'",
                e,
            )
            return False

        return True
