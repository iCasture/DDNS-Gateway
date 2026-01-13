"""
Tencent Cloud DNSPod provider implementation.

This module implements the Tencent Cloud DNSPod API using the official SDK.
Only supports China mainland DNSPod (not international version api.dnspod.com).
Endpoint: dnspod.tencentcloudapi.com
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client_async, models

from ddns_gateway.normalize import comments_equal, normalize_upstream_value
from ddns_gateway.providers.base import BaseDNSProvider, ProviderError, ProviderResult
from ddns_gateway.types import DesiredState, ExistingRecord, UpstreamResult

if TYPE_CHECKING:
    from typing import Any, Final

    from ddns_gateway.models import RecordType


# Tencent Cloud DNSPod endpoint
DNSPOD_ENDPOINT: Final[str] = "dnspod.tencentcloudapi.com"


logger = logging.getLogger(__name__)


class TencentProvider(BaseDNSProvider):
    """
    Tencent Cloud DNSPod provider.

    Uses the official tencentcloud-sdk-python-dnspod SDK.
    Supports the Remark field directly in ModifyRecord API.

    Note: Only supports China mainland DNSPod, not international version.
    """

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "tencent"

    def _create_client(
        self,
        secret_id: str,
        secret_key: str,
    ) -> dnspod_client_async.DnspodClient:
        """
        Create a Tencent Cloud DNSPod client.

        Parameters
        ----------
        secret_id : str
            Tencent Cloud Secret ID.
        secret_key : str
            Tencent Cloud Secret Key.

        Returns
        -------
        DnspodClient
            The DNSPod client instance.
        """
        cred = credential.Credential(secret_id, secret_key)
        http_profile = HttpProfile()
        http_profile.endpoint = DNSPOD_ENDPOINT

        client_profile = ClientProfile()
        client_profile.httpProfile = http_profile

        return dnspod_client_async.DnspodClient(cred, "", client_profile)

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
        secret_id = credentials.get("id")
        secret_key = credentials.get("secret")

        if not secret_id or not secret_key:
            msg = "Missing required credentials: id and secret"
            raise ProviderError(msg)

        client = self._create_client(secret_id, secret_key)
        records = await self._describe_records(client, zone, record, record_type)

        if records is None:
            msg = "Failed to query DNS records from Tencent API"
            raise ProviderError(msg)

        if len(records) == 0:
            return None

        if len(records) > 1:
            msg = f"Multiple records found for {record}.{zone} ({record_type.value}), manual resolution required"
            raise ProviderError(msg)

        raw = records[0]
        return ExistingRecord(
            record_id=str(raw.get("record_id", "")),
            zone_id=None,  # Tencent does not use zone_id
            value=normalize_upstream_value(
                str(raw.get("value", "")),
                record_type.value,
            ),
            ttl=int(raw.get("ttl", 0)),
            comment=raw.get("remark"),
            proxied=None,  # Not supported by Tencent
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
        secret_id = credentials.get("id")
        secret_key = credentials.get("secret")

        if not secret_id or not secret_key:
            return UpstreamResult(
                success=False,
                action="created",
                message="Missing required credentials: id and secret",
            )

        client = self._create_client(secret_id, secret_key)

        # Delegate to legacy _create_record helper
        result = await self._create_record(
            client,
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
            The DNS zone (normalized). Required by Tencent API.
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
        secret_id = credentials.get("id")
        secret_key = credentials.get("secret")

        if not secret_id or not secret_key:
            return UpstreamResult(
                success=False,
                action="updated",
                message="Missing required credentials: id and secret",
            )

        client = self._create_client(secret_id, secret_key)

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
                message=f"DNS record unchanged for {existing.raw.get('name', '')}",
                record_id=existing.record_id,
                zone_id=None,
            )

        try:
            request = models.ModifyRecordRequest()
            request.Domain = zone
            request.RecordId = int(existing.record_id)
            request.SubDomain = existing.raw.get("name", "")
            request.RecordType = record_type
            request.RecordLine = existing.raw.get("line", "默认")
            request.Value = desired.value
            request.TTL = desired.ttl
            if desired.comment is not None:
                request.Remark = desired.comment

            response = await client.ModifyRecord(request)
            request_id = response.RequestId

            logger.debug("[tencent] ModifyRecord -> RequestId: %s", request_id)

            return UpstreamResult(
                success=True,
                action="updated",
                message=f"DNS record updated for {existing.raw.get('name', '')}.{zone}",
                record_id=existing.record_id,
                zone_id=None,
                previous_value=existing.value if value_changed else None,
                extra={"request_id": request_id} if request_id else None,
            )

        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[tencent: ModifyRecord] Failed to update: '%s'",
                e,
            )
            return UpstreamResult(
                success=False,
                action="updated",
                message=f"Failed to update record: {e}",
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
            The DNS zone (normalized). Required by Tencent API.
        existing : ExistingRecord
            The existing record to delete.
        credentials : dict[str, str]
            Must contain "id" and "secret".

        Returns
        -------
        UpstreamResult
            The result of the delete operation.
        """
        secret_id = credentials.get("id")
        secret_key = credentials.get("secret")

        if not secret_id or not secret_key:
            return UpstreamResult(
                success=False,
                action="deleted",
                message="Missing required credentials: id and secret",
            )

        client = self._create_client(secret_id, secret_key)

        try:
            request = models.DeleteRecordRequest()
            request.Domain = zone
            request.RecordId = int(existing.record_id)

            response = await client.DeleteRecord(request)
            request_id = response.RequestId

            logger.debug("[tencent] DeleteRecord -> RequestId: %s", request_id)

            return UpstreamResult(
                success=True,
                action="deleted",
                message=f"DNS record deleted for {existing.raw.get('name', '')}.{zone}",
                record_id=existing.record_id,
                zone_id=None,
                extra={"request_id": request_id} if request_id else None,
            )

        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[tencent: DeleteRecord] Failed to delete: '%s'",
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
        Update or create a DNS record in Tencent Cloud DNSPod.

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
            Must contain "tc_secret_id" and "tc_secret_key".
        comment : str | None, optional
            Optional remark for the record.

        Returns
        -------
        ProviderResult
            The result of the operation.
        """
        secret_id = credentials.get("tc_secret_id")
        secret_key = credentials.get("tc_secret_key")

        if not secret_id or not secret_key:
            return ProviderResult(
                success=False,
                message="Missing required credentials: tc_secret_id, tc_secret_key",
            )

        # Normalize record name for DNSPod (@ for root, others as-is)
        sub = "@" if record in {"@", ""} else record

        try:
            async with self._create_client(secret_id, secret_key) as client:
                # Step 1: Query existing records
                records = await self._describe_records(client, zone, sub, record_type)

                if records is None:
                    return ProviderResult(
                        success=False,
                        message="Failed to query DNS records",
                    )

                logger.debug(
                    "[tencent] Found %d records for %s.%s %s",
                    len(records),
                    sub,
                    zone,
                    record_type,
                )

                # Step 2: Handle based on number of records found
                if len(records) == 0:
                    # Create new record
                    return await self._create_record(
                        client,
                        zone,
                        sub,
                        record_type,
                        value,
                        ttl,
                        comment,
                    )
                if len(records) == 1:
                    # Update existing record
                    return await self._update_or_skip(
                        client,
                        zone,
                        records[0],
                        value,
                        ttl,
                        comment,
                    )
                # Multiple records found - error
                return ProviderResult(
                    success=False,
                    message=(
                        f"Multiple records ({len(records)}) found for "
                        f"{sub}.{zone} {record_type}. "
                        "Please manually clean up duplicate records."
                    ),
                )

        except Exception as e:  # noqa: BLE001
            logger.error("[tencent] Failed to query/manipulate records: '%s'", e)  # noqa: TRY400
            return ProviderResult(
                success=False,
                message=f"Tencent Cloud DNSPod error: {e}",
            )

    async def _describe_records(
        self,
        client: dnspod_client_async.DnspodClient,
        zone: str,
        record_name: str,
        record_type: RecordType,
    ) -> list[dict[str, Any]] | None:
        """
        Query DNS records.

        Parameters
        ----------
        client : DnspodClient
            The DNSPod client.
        zone : str
            The DNS zone name.
        record_name : str
            The host record name.
        record_type : RecordType
            The record type.

        Returns
        -------
        list[dict[str, Any]] | None
            List of matching records or None on error.
        """
        try:
            request = models.DescribeRecordListRequest()
            request.Domain = zone
            request.Subdomain = record_name
            request.RecordType = record_type.value

            response = await client.DescribeRecordList(request)
            logger.debug(
                "[tencent] DescribeRecordList -> RequestId: %s",
                response.RequestId,
            )
            logger.debug(
                "[tencent] Response: RecordCountInfo=%s",
                response.RecordCountInfo,
            )

            if response.RecordList is None:
                return []

            return [
                {
                    "record_id": r.RecordId,
                    "name": r.Name,
                    "value": r.Value,
                    "type": r.Type,
                    "ttl": r.TTL,
                    "remark": r.Remark,
                    "line": r.Line,
                    "line_id": r.LineId,
                }
                for r in response.RecordList
                if r.Name == record_name and r.Type == record_type.value
            ]

        except Exception as e:  # noqa: BLE001
            # Handle "no records found" as empty list, not error
            error_msg = str(e)
            if "ResourceNotFound.NoDataOfRecord" in error_msg:
                logger.debug("[tencent] No records found (not an error)")
                return []
            logger.error(  # noqa: TRY400
                "[tencent: DescribeRecordList] Failed to describe record list: '%s'",
                e,
            )
            return None

    async def _create_record(
        self,
        client: dnspod_client_async.DnspodClient,
        zone: str,
        record_name: str,
        record_type: RecordType,
        value: str,
        ttl: int | None,
        comment: str | None,
    ) -> ProviderResult:
        """
        Create a new DNS record.

        Parameters
        ----------
        client : DnspodClient
            The DNSPod client.
        zone : str
            The DNS zone name.
        record_name : str
            The host record name.
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
            request = models.CreateRecordRequest()
            request.Domain = zone
            request.SubDomain = record_name
            request.RecordType = record_type.value
            request.RecordLine = "默认"
            request.Value = value
            request.TTL = ttl
            if comment:
                request.Remark = comment

            response = await client.CreateRecord(request)
            record_id = str(response.RecordId) if response.RecordId else None
            request_id = response.RequestId

            logger.debug(
                "[tencent] CreateRecord -> RequestId: %s, RecordId: %s",
                request_id,
                record_id,
            )

            return ProviderResult(
                success=True,
                message=f"DNS record created for {record_name}.{zone}",
                action="created",
                record_id=record_id,
                request_id=request_id,
            )

        except Exception as e:  # noqa: BLE001
            logger.error("[tencent: CreateRecord] Failed to create record: '%s'", e)  # noqa: TRY400
            return ProviderResult(
                success=False,
                message=f"Failed to create record: {e}",
            )

    async def _update_or_skip(
        self,
        client: dnspod_client_async.DnspodClient,
        zone: str,
        existing: dict[str, Any],
        value: str,
        ttl: int | None,
        comment: str | None,
    ) -> ProviderResult:
        """
        Update an existing record or skip if unchanged.

        Parameters
        ----------
        client : DnspodClient
            The DNSPod client.
        zone : str
            The DNS zone name.
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
        current_remark = existing.get("remark", "") or ""
        record_name = existing["name"]
        record_type = existing["type"]
        record_line = existing.get("line", "默认")

        # Check if update is needed
        value_changed = current_value != value
        # If ttl / comment None, it implies "keep existing", so we don't treat it as a change.
        # We only flag a change if ttl is explicitly provided (not None) and differs.
        ttl_changed = ttl is not None and current_ttl != ttl
        remark_changed = comment is not None and current_remark != comment

        if not value_changed and not ttl_changed and not remark_changed:
            return ProviderResult(
                success=True,
                message=f"DNS record unchanged for {record_name}.{zone}",
                action="unchanged",
                record_id=str(record_id),
            )

        try:
            request = models.ModifyRecordRequest()
            request.Domain = zone
            request.RecordId = record_id
            request.SubDomain = record_name
            request.RecordType = record_type
            request.RecordLine = record_line
            request.Value = value
            request.TTL = ttl
            if comment is not None:
                request.Remark = comment

            response = await client.ModifyRecord(request)
            request_id = response.RequestId

            logger.debug("[tencent] ModifyRecord -> RequestId: %s", request_id)

            return ProviderResult(
                success=True,
                message=f"DNS record updated for {record_name}.{zone}",
                action="updated",
                record_id=str(record_id),
                request_id=request_id,
                previous_value=current_value if value_changed else None,
            )

        except Exception as e:  # noqa: BLE001
            logger.error("[tencent: ModifyRecord] Failed to update record: '%s'", e)  # noqa: TRY400
            return ProviderResult(
                success=False,
                message=f"Failed to update record: {e}",
            )
