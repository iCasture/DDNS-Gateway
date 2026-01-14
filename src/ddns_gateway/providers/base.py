"""
Base class for DNS providers.

This module defines the abstract base class that all DNS provider
implementations must inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ddns_gateway.models import RecordType
    from ddns_gateway.types import DesiredState, ExistingRecord, UpstreamResult


class ProviderError(Exception):
    """
    Exception raised when a provider operation fails.

    This exception is used for errors that should propagate up to callers,
    such as missing credentials, zone not found, or multiple records found.

    Attributes
    ----------
    message : str
        Human-readable error message.
    code : str | None
        Optional machine-readable error code.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        """
        Initialize a ProviderError.

        Parameters
        ----------
        message : str
            Error message.
        code : str | None, optional
            Error code.
        """
        super().__init__(message)
        self.message = message
        self.code = code


class BaseDNSProvider(ABC):
    """
    Abstract base class for DNS providers.

    All DNS provider implementations must inherit from this class
    and implement the required abstract methods.
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

    @abstractmethod
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
            Provider-specific credentials.
        timeout_sec : float | None
            HTTP request timeout in seconds. `None` = use SDK/provider default.

        Returns
        -------
        ExistingRecord | None
            The existing record if found, None otherwise.
            If multiple records match, raises ProviderError.

        Raises
        ------
        ProviderError
            If multiple records match or other provider errors occur.
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
            Provider-specific credentials.
        timeout_sec : float | None
            HTTP request timeout in seconds. `None` = use SDK/provider default.

        Returns
        -------
        UpstreamResult
            The result of the create operation.
        """
        ...

    @abstractmethod
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
            The DNS zone (normalized).
        existing : ExistingRecord
            The existing record to update.
        desired : DesiredState
            The desired state for the record.
        credentials : dict[str, str]
            Provider-specific credentials.
        timeout_sec : float | None
            HTTP request timeout in seconds. `None` = use SDK/provider default.

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
        timeout_sec: float | None = None,
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
        timeout_sec : float | None
            HTTP request timeout in seconds. `None` = use SDK/provider default.

        Returns
        -------
        UpstreamResult
            The result of the delete operation.
        """
        ...

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
