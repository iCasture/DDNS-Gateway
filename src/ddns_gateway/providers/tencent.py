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

from ddns_gateway.models import RecordType
from ddns_gateway.providers.base import BaseDNSProvider, ProviderResult

if TYPE_CHECKING:
    from typing import Any, Final


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
        sub = "@" if record == "@" or record == "" else record

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

        except Exception as e:
            logger.error("[tencent] Failed to query/manipulate records: '%s'", e)
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

        except Exception as e:
            # Handle "no records found" as empty list, not error
            error_msg = str(e)
            if "ResourceNotFound.NoDataOfRecord" in error_msg:
                logger.debug("[tencent] No records found (not an error)")
                return []
            logger.error(
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

        except Exception as e:
            logger.error("[tencent: CreateRecord] Failed to create record: '%s'", e)
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

        except Exception as e:
            logger.error("[tencent: ModifyRecord] Failed to update record: '%s'", e)
            return ProviderResult(
                success=False,
                message=f"Failed to update record: {e}",
            )
