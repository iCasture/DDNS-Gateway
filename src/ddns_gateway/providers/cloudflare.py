"""
CloudFlare DNS provider implementation.

This module implements the CloudFlare DNS API v4 for updating DNS records.
Only API Token authentication is supported (not Global API Key).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from starlette import status as st_status

from ddns_gateway.models import WarningCode, WarningModel
from ddns_gateway.normalize import comments_equal, normalize_upstream_value
from ddns_gateway.providers.base import BaseDNSProvider, ProviderError
from ddns_gateway.types import DesiredState, ExistingRecord, UpstreamResult

if TYPE_CHECKING:
    from typing import Final

    from ddns_gateway.models import RecordType


# CloudFlare API base URL
CF_API_BASE: Final[str] = "https://api.cloudflare.com/client/v4"

# HTTP timeout in seconds
HTTP_TIMEOUT: Final[float] = 30.0


logger = logging.getLogger(__name__)


class CloudFlareProvider(BaseDNSProvider):
    """
    CloudFlare DNS provider.

    Uses CloudFlare API v4 with API Token authentication.
    Supports the `comment` field for DNS records.
    """

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "cloudflare"

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
            Must contain "secret".

        Returns
        -------
        ExistingRecord | None
            The existing record if found, None otherwise.

        Raises
        ------
        ProviderError
            If multiple records found or API error.
        """
        cf_token = credentials.get("secret")
        if not cf_token:
            msg = "Missing required credential: secret"
            raise ProviderError(msg)

        headers = {
            "Authorization": f"Bearer {cf_token}",
            "Content-Type": "application/json",
        }

        fqdn = self.build_fqdn(zone, record)

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            # Get Zone ID
            zone_id = await self._get_zone_id(client, headers, zone)
            if zone_id is None:
                msg = f"Zone not found for domain: {zone}"
                raise ProviderError(msg)

            # Query existing records
            records = await self._get_records(
                client,
                headers,
                zone_id,
                fqdn,
                record_type,
            )

            if records is None:
                msg = "Failed to query DNS records"
                raise ProviderError(msg)

            if len(records) == 0:
                return None

            if len(records) > 1:
                msg = (
                    f"Multiple records ({len(records)}) found for {fqdn} {record_type}. "
                    "Please manually clean up duplicate records."
                )
                raise ProviderError(msg)

            # Convert to ExistingRecord
            raw = records[0]
            return ExistingRecord(
                record_id=str(raw.get("id", "")),
                zone_id=zone_id,
                value=normalize_upstream_value(
                    raw.get("content", ""),
                    record_type.value,
                ),
                ttl=int(raw.get("ttl", 0)),
                comment=raw.get("comment"),
                proxied=raw.get("proxied"),
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
            Must contain "secret".

        Returns
        -------
        UpstreamResult
            The result of the create operation.
        """
        cf_token = credentials.get("secret")
        if not cf_token:
            return UpstreamResult(
                success=False,
                action="created",
                message="Missing required credential: secret",
            )

        headers = {
            "Authorization": f"Bearer {cf_token}",
            "Content-Type": "application/json",
        }

        fqdn = self.build_fqdn(zone, record)

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            # Get Zone ID
            zone_id = await self._get_zone_id(client, headers, zone)
            if zone_id is None:
                return UpstreamResult(
                    success=False,
                    action="created",
                    message=f"Zone not found for domain: {zone}",
                )

            url = f"{CF_API_BASE}/zones/{zone_id}/dns_records"

            # Determine proxied value
            warnings: list[WarningModel] = []
            proxied = self._resolve_proxied(
                desired.proxied,
                record_type.value,
                warnings,
            )

            payload: dict[str, str | int | bool] = {
                "type": record_type.value,
                "name": fqdn,
                "content": desired.value,
                "proxied": proxied,
            }
            if desired.ttl is not None:
                payload["ttl"] = desired.ttl
            if desired.comment:
                payload["comment"] = desired.comment

            try:
                response = await client.post(url, headers=headers, json=payload)
                logger.debug("[cloudflare] POST %s -> %d", url, response.status_code)
                logger.debug("[cloudflare] Response: %s", response.text)

                data = response.json()

                if response.status_code == st_status.HTTP_200_OK and data.get(
                    "success",
                ):
                    result = data.get("result", {})
                    return UpstreamResult(
                        success=True,
                        action="created",
                        message=f"DNS record created for {fqdn}",
                        record_id=str(result.get("id", "")),
                        zone_id=zone_id,
                        http_status=response.status_code,
                        extra={"cf_ray": response.headers.get("cf-ray", "")},
                        warnings=warnings,
                    )
                errors = data.get("errors", [])
                error_msg = (
                    errors[0].get("message", "Unknown error")
                    if errors
                    else "Unknown error"
                )
                return UpstreamResult(
                    success=False,
                    action="created",
                    message=f"Failed to create record: {error_msg}",
                    zone_id=zone_id,
                    http_status=response.status_code,
                    warnings=warnings,
                )

            except httpx.RequestError as e:
                logger.error(  # noqa: TRY400
                    "[cloudflare: CreateRecord] Network request failed: '%s'",
                    e,
                )
                return UpstreamResult(
                    success=False,
                    action="created",
                    message=f"Request error: {e}",
                    warnings=warnings,
                )

    async def update_record(
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
            but Cloudflare uses the zone_id from the existing record instead.
        existing : ExistingRecord
            The existing record to update.
        desired : DesiredState
            The desired state for the record.
        credentials : dict[str, str]
            Must contain "secret".

        Returns
        -------
        UpstreamResult
            The result of the update operation.
        """
        # Unused, as we use record_id/zone_id from ExistingRecord
        _ = zone

        cf_token = credentials.get("secret")
        if not cf_token:
            return UpstreamResult(
                success=False,
                action="updated",
                message="Missing required credential: secret",
            )

        headers = {
            "Authorization": f"Bearer {cf_token}",
            "Content-Type": "application/json",
        }

        # Check if update is needed
        # Normalize desired value and existing value for comparison
        record_type = existing.raw.get("type", "")
        desired_value_normalized = normalize_upstream_value(desired.value, record_type)

        value_changed = existing.value != desired_value_normalized
        ttl_changed = desired.ttl is not None and existing.ttl != desired.ttl
        comment_changed = desired.comment is not None and not comments_equal(
            existing.comment,
            desired.comment,
        )

        # Handle proxied
        warnings: list[WarningModel] = []
        proxied = self._resolve_proxied(desired.proxied, record_type, warnings)
        proxied_changed = proxied is not None and existing.proxied != proxied

        if (
            not value_changed
            and not ttl_changed
            and not comment_changed
            and not proxied_changed
        ):
            return UpstreamResult(
                success=True,
                action="nochange",
                message=f"DNS record unchanged for {existing.raw.get('name', '')}",
                record_id=existing.record_id,
                zone_id=existing.zone_id,
                warnings=warnings,
            )

        url = f"{CF_API_BASE}/zones/{existing.zone_id}/dns_records/{existing.record_id}"
        record_name = existing.raw.get("name", "")

        payload: dict[str, str | int | bool] = {
            "type": record_type,
            "name": record_name,
            "content": desired.value,
            "proxied": proxied if proxied is not None else existing.proxied or False,
        }
        if desired.ttl is not None:
            payload["ttl"] = desired.ttl
        if desired.comment is not None:
            payload["comment"] = desired.comment

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.patch(url, headers=headers, json=payload)
                logger.debug("[cloudflare] PATCH %s -> %d", url, response.status_code)
                logger.debug("[cloudflare] Response: %s", response.text)

                data = response.json()

                if response.status_code == st_status.HTTP_200_OK and data.get(
                    "success",
                ):
                    return UpstreamResult(
                        success=True,
                        action="updated",
                        message=f"DNS record updated for {record_name}",
                        record_id=existing.record_id,
                        zone_id=existing.zone_id,
                        previous_value=existing.value if value_changed else None,
                        http_status=response.status_code,
                        extra={"cf_ray": response.headers.get("cf-ray", "")},
                        warnings=warnings,
                    )
                errors = data.get("errors", [])
                error_msg = (
                    errors[0].get("message", "Unknown error")
                    if errors
                    else "Unknown error"
                )
                return UpstreamResult(
                    success=False,
                    action="updated",
                    message=f"Failed to update record: {error_msg}",
                    zone_id=existing.zone_id,
                    http_status=response.status_code,
                    warnings=warnings,
                )

        except httpx.RequestError as e:
            logger.error(  # noqa: TRY400
                "[cloudflare: UpdateRecord] Network request failed: '%s'",
                e,
            )
            return UpstreamResult(
                success=False,
                action="updated",
                message=f"Request error: {e}",
                warnings=warnings,
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
            but Cloudflare uses the zone_id from the existing record instead.
        existing : ExistingRecord
            The existing record to delete.
        credentials : dict[str, str]
            Must contain "secret".

        Returns
        -------
        UpstreamResult
            The result of the delete operation.
        """
        # Unused, as we use record_id/zone_id from ExistingRecord
        _ = zone

        cf_token = credentials.get("secret")
        if not cf_token:
            return UpstreamResult(
                success=False,
                action="deleted",
                message="Missing required credential: secret",
            )

        headers = {
            "Authorization": f"Bearer {cf_token}",
            "Content-Type": "application/json",
        }

        url = f"{CF_API_BASE}/zones/{existing.zone_id}/dns_records/{existing.record_id}"
        record_name = existing.raw.get("name", "")

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.delete(url, headers=headers)
                logger.debug("[cloudflare] DELETE %s -> %d", url, response.status_code)
                logger.debug("[cloudflare] Response: %s", response.text)

                data = response.json()

                if response.status_code == st_status.HTTP_200_OK and data.get(
                    "success",
                ):
                    return UpstreamResult(
                        success=True,
                        action="deleted",
                        message=f"DNS record deleted for {record_name}",
                        record_id=existing.record_id,
                        zone_id=existing.zone_id,
                        http_status=response.status_code,
                        extra={"cf_ray": response.headers.get("cf-ray", "")},
                    )
                errors = data.get("errors", [])
                error_msg = (
                    errors[0].get("message", "Unknown error")
                    if errors
                    else "Unknown error"
                )
                return UpstreamResult(
                    success=False,
                    action="deleted",
                    message=f"Failed to delete record: {error_msg}",
                    zone_id=existing.zone_id,
                    http_status=response.status_code,
                )

        except httpx.RequestError as e:
            logger.error(  # noqa: TRY400
                "[cloudflare: DeleteRecord] Network request failed: '%s'",
                e,
            )
            return UpstreamResult(
                success=False,
                action="deleted",
                message=f"Request error: {e}",
            )

    def _resolve_proxied(
        self,
        proxied: bool | None,  # noqa: FBT001
        record_type: str,
        warnings: list,  # type: ignore[type-arg]
    ) -> bool:
        """
        Resolve proxied value based on record type.

        Proxied is only valid for A, AAAA, CNAME records.
        For TXT records, proxied is always False and a warning is generated.

        Parameters
        ----------
        proxied : bool | None
            Requested proxied status.
        record_type : str
            The record type.
        warnings : list
            List to append warnings to.

        Returns
        -------
        bool
            Resolved proxied value.
        """
        # TXT records cannot be proxied
        if record_type.upper() == "TXT":
            if proxied is True:
                warnings.append(
                    WarningModel(
                        code=WarningCode.CF_PROXIED_IGNORED_FOR_TXT,
                        message="Proxied parameter ignored for TXT records",
                        field="proxied",
                    ),
                )
            return False

        # For A, AAAA, CNAME: use provided value or default to False
        return proxied if proxied is not None else False

    async def _get_zone_id(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        zone: str,
    ) -> str | None:
        """
        Get the Zone ID for a domain.

        Parameters
        ----------
        client : httpx.AsyncClient
            HTTP client.
        headers : dict[str, str]
            Request headers.
        zone : str
            The DNS zone name.

        Returns
        -------
        str | None
            Zone ID or None if not found.
        """
        url = f"{CF_API_BASE}/zones"
        params = {"name": zone}

        try:
            response = await client.get(url, headers=headers, params=params)
        except httpx.RequestError as e:
            logger.error("[cloudflare] Network request failed: '%s'", e)  # noqa: TRY400
            return None

        logger.debug(
            "[cloudflare] GET %s?name=%s -> %d",
            url,
            zone,
            response.status_code,
        )

        if response.status_code != st_status.HTTP_200_OK:
            logger.error("[cloudflare] Failed to get zones: '%s'", response.text)
            return None

        data = response.json()
        logger.debug("[cloudflare] Response: %s", response.text)

        if not data.get("success"):
            return None

        zones = data.get("result", [])
        if zones:
            return str(zones[0]["id"])
        return None

    async def _get_records(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        zone_id: str,
        fqdn: str,
        record_type: RecordType,
    ) -> list[dict] | None:  # type: ignore[type-arg]
        """
        Get DNS records matching the criteria.

        Parameters
        ----------
        client : httpx.AsyncClient
            HTTP client.
        headers : dict[str, str]
            Request headers.
        zone_id : str
            The zone ID.
        fqdn : str
            The fully qualified domain name.
        record_type : RecordType
            The record type.

        Returns
        -------
        list[dict] | None
            List of records or None on error.
        """
        url = f"{CF_API_BASE}/zones/{zone_id}/dns_records"
        params = {"name": fqdn, "type": record_type.value}

        try:
            response = await client.get(url, headers=headers, params=params)
            logger.debug(
                "[cloudflare] GET %s?name=%s&type=%s -> %d",
                url,
                fqdn,
                record_type,
                response.status_code,
            )

            if response.status_code != st_status.HTTP_200_OK:
                logger.error("[cloudflare] Failed to get records: '%s'", response.text)
                return None

            data = response.json()
            logger.debug("[cloudflare] Response: %s", response.text)

            if not data.get("success"):
                return None

            return list(data.get("result", []))

        except httpx.RequestError as e:
            logger.error("[cloudflare] Network request failed: '%s'", e)  # noqa: TRY400
            return None
