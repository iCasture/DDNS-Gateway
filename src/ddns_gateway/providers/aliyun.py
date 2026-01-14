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
from ddns_gateway.providers.base import BaseDNSProvider, ProviderError
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

    async def find_record(
        self,
        zone: str,
        record: str,
        record_type: RecordType,
        credentials: dict[str, str],
        timeout_sec: float | None = None,
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
        timeout_sec : float | None
            Request timeout in seconds. `None` = use SDK default.

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
        if timeout_sec is not None:
            timeout_ms = int(timeout_sec * 1000)
            runtime = util_models.RuntimeOptions(
                read_timeout=timeout_ms,
                connect_timeout=timeout_ms,
            )
        else:
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
        timeout_sec: float | None = None,
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
        timeout_sec : float | None
            Request timeout in seconds. `None` = use SDK default.

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
        if timeout_sec is not None:
            timeout_ms = int(timeout_sec * 1000)
            runtime = util_models.RuntimeOptions(
                read_timeout=timeout_ms,
                connect_timeout=timeout_ms,
            )
        else:
            runtime = util_models.RuntimeOptions()

        try:
            request = alidns_models.AddDomainRecordRequest(
                domain_name=zone,
                rr=record,
                type=record_type.value,
                value=desired.value,
            )
            if desired.ttl is not None:
                request.ttl = desired.ttl
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
            if desired.comment and record_id:
                remark_result = await self._update_record_remark(
                    client,
                    runtime,
                    record_id,
                    desired.comment,
                )
                if not remark_result:
                    warnings.append(
                        WarningModel(
                            code=WarningCode.ALI_COMMENT_UPDATE_FAILED,
                            message="Record created but failed to set remark",
                        ),
                    )

            return UpstreamResult(
                success=True,
                action="created",
                message=f"DNS record created for {record}.{zone}",
                record_id=record_id,
                zone_id=None,
                extra={"request_id": request_id} if request_id else None,
                warnings=warnings,
            )

        except Exception as e:  # noqa: BLE001
            logger.error(  # noqa: TRY400
                "[aliyun: AddDomainRecord] Failed to add domain record: '%s'",
                e,
            )
            return UpstreamResult(
                success=False,
                action="created",
                message=f"Failed to create record: {e}",
            )

    async def update_record(
        self,
        zone: str,
        existing: ExistingRecord,
        desired: DesiredState,
        credentials: dict[str, str],
        timeout_sec: float | None = None,
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
        timeout_sec : float | None
            Request timeout in seconds. `None` = use SDK default.

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
        if timeout_sec is not None:
            timeout_ms = int(timeout_sec * 1000)
            runtime = util_models.RuntimeOptions(
                read_timeout=timeout_ms,
                connect_timeout=timeout_ms,
            )
        else:
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
            warnings=warnings,
        )

    async def delete_record(
        self,
        zone: str,
        existing: ExistingRecord,
        credentials: dict[str, str],
        timeout_sec: float | None = None,
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
        timeout_sec : float | None
            Request timeout in seconds. `None` = use SDK default.

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
        if timeout_sec is not None:
            timeout_ms = int(timeout_sec * 1000)
            runtime = util_models.RuntimeOptions(
                read_timeout=timeout_ms,
                connect_timeout=timeout_ms,
            )
        else:
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
