"""
Base class for DNS providers.

This module defines the abstract base class that all DNS provider
implementations must inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ddns_gateway.models import ProviderMetadata, RecordType, WarningModel

if TYPE_CHECKING:
    from ddns_gateway.types import DesiredState, ExistingRecord, UpstreamResult


class ProviderResult:
    """
    Result of a provider operation (legacy).

    This class is kept for backward compatibility with existing code.
    New code should use UpstreamResult from types.py instead.

    Attributes
    ----------
    success : bool
        Whether the operation was successful.
    action : str | None
        The action taken ("created", "updated", "unchanged").
    message : str
        Human-readable message.
    record_id : str | None
        The record ID from the provider.
    request_id : str | None
        The request ID from the provider.
    zone_id : str | None
        The zone ID (CloudFlare).
    previous_value : str | None
        The previous record value.
    extra : dict[str, str] | None
        Additional metadata.
    warnings : list[WarningModel]
        List of warnings.
    """

    def __init__(
        self,
        *,
        success: bool,
        message: str,
        action: str | None = None,
        record_id: str | None = None,
        request_id: str | None = None,
        zone_id: str | None = None,
        previous_value: str | None = None,
        extra: dict[str, str] | None = None,
        warnings: list[WarningModel] | None = None,
    ) -> None:
        """
        Initialize a ProviderResult.

        Parameters
        ----------
        success : bool
            Whether the operation was successful.
        message : str
            Human-readable message.
        action : str | None, optional
            The action taken.
        record_id : str | None, optional
            The record ID.
        request_id : str | None, optional
            The request ID.
        zone_id : str | None, optional
            The zone ID.
        previous_value : str | None, optional
            The previous record value.
        extra : dict[str, str] | None, optional
            Additional metadata.
        warnings : list[WarningModel] | None, optional
            List of warnings.
        """
        self.success = success
        self.message = message
        self.action = action
        self.record_id = record_id
        self.request_id = request_id
        self.zone_id = zone_id
        self.previous_value = previous_value
        self.extra = extra
        self.warnings = warnings or []

    def to_metadata(self) -> ProviderMetadata:
        """
        Convert to ProviderMetadata.

        Returns
        -------
        ProviderMetadata
            Provider metadata object.
        """
        return ProviderMetadata(
            record_id=self.record_id,
            request_id=self.request_id,
            zone_id=self.zone_id,
            extra=self.extra,
        )


class BaseDNSProvider(ABC):
    """
    Abstract base class for DNS providers.

    All DNS provider implementations must inherit from this class
    and implement the required abstract methods.

    The new interface (find_record, create_record, update_record_v2, delete_record)
    is designed for the refactored API. The legacy update_record method is kept
    for backward compatibility during the transition.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Get the provider name.

        Returns
        -------
        str
            Provider name identifier (lowercase).
        """
        ...

    # =========================================================================
    # New Interface (Phase 2 Refactoring)
    # =========================================================================

    @abstractmethod
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
            The DNS zone (normalized, e.g., "example.com").
        record : str
            The host record name (normalized, e.g., "home", "@").
        record_type : RecordType
            The record type (A, AAAA, CNAME, TXT).
        credentials : dict[str, str]
            Provider-specific credentials.

        Returns
        -------
        ExistingRecord | None
            The existing record if found, None otherwise.

        Raises
        ------
        ProviderError
            If multiple matching records are found or an API error occurs.
        """
        ...

    @abstractmethod
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
            The record type (A, AAAA, CNAME, TXT).
        desired : DesiredState
            The desired state for the record.
        credentials : dict[str, str]
            Provider-specific credentials.

        Returns
        -------
        UpstreamResult
            The result of the create operation.
        """
        ...

    @abstractmethod
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
            The DNS zone (normalized).
        existing : ExistingRecord
            The existing record to update.
        desired : DesiredState
            The desired state for the record.
        credentials : dict[str, str]
            Provider-specific credentials.

        Returns
        -------
        UpstreamResult
            The result of the update operation.
        """
        ...

    @abstractmethod
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
            The DNS zone (normalized).
        existing : ExistingRecord
            The existing record to delete.
        credentials : dict[str, str]
            Provider-specific credentials.

        Returns
        -------
        UpstreamResult
            The result of the delete operation.
        """
        ...

    # =========================================================================
    # Legacy Interface (kept for backward compatibility)
    # =========================================================================

    @abstractmethod
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
        Update or create a DNS record (legacy interface).

        This method is kept for backward compatibility. New code should use
        the find_record + create_record/update_record_v2 pattern instead.

        This method should:
        1. Query existing records matching zone + record + type
        2. If 0 records: create a new record
        3. If 1 record: update if value differs, or return unchanged
        4. If multiple records: return error

        Parameters
        ----------
        zone : str
            The DNS zone (root domain name, e.g., "example.com").
        record : str
            The host record name (e.g., "home", "@").
        record_type : RecordType
            The record type (A, AAAA, CNAME, TXT).
        value : str
            The record value to set.
        ttl : int | None
            Time to live in seconds, or None to use provider default.
        credentials : dict[str, str]
            Provider-specific credentials.
        comment : str | None, optional
            Optional comment/remark for the record.

        Returns
        -------
        ProviderResult
            The result of the operation.
        """
        ...

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def build_fqdn(self, zone: str, record: str) -> str:
        """
        Build the fully qualified domain name.

        Parameters
        ----------
        zone : str
            The DNS zone (root domain).
        record : str
            The host record name.

        Returns
        -------
        str
            The FQDN.
        """
        if record in {"@", ""}:
            return zone
        return f"{record}.{zone}"
