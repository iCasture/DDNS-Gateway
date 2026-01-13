"""
Core data types for DDNS Gateway.

This module defines the fundamental data structures used across the application,
including record identification, upstream results, and desired state models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ddns_gateway.models import WarningModel


@dataclass(frozen=True)
class RecordIdentity:
    """
    Unique identifier for a DNS record.

    This immutable data class represents the canonical identity of a DNS record,
    used for deduplication and caching purposes.

    Attributes
    ----------
    provider : str
        The DNS provider name (lowercase, e.g., "cloudflare").
    zone : str
        The DNS zone (normalized, e.g., "example.com").
    record_type : str
        The record type (uppercase, e.g., "A", "AAAA").
    record : str
        The host record name (normalized, e.g., "home", "@").
    """

    provider: str
    zone: str
    record_type: str
    record: str


@dataclass
class ExistingRecord:
    """
    Existing DNS record retrieved from upstream provider.

    This data class represents a DNS record as it currently exists in the
    provider's system, with all values normalized for comparison.

    Attributes
    ----------
    record_id : str
        The unique record ID from the provider.
    zone_id : str | None
        The zone ID (Cloudflare specific).
    value : str
        The record value (normalized).
    ttl : int
        The TTL value in seconds.
    comment : str | None
        The record comment/remark.
    proxied : bool | None
        The Cloudflare proxy status (Cloudflare only, A/AAAA/CNAME).
    raw : dict[str, Any]
        The raw response from the provider for debugging.
    """

    record_id: str
    zone_id: str | None
    value: str
    ttl: int
    comment: str | None
    proxied: bool | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class DesiredState:
    """
    Desired state for a DNS record.

    This data class represents the target state that the user wants to
    achieve for a DNS record.

    Attributes
    ----------
    value : str
        The desired record value.
    ttl : int | None
        The desired TTL value in seconds, or None for provider default.
    comment : str | None
        The desired comment/remark (must be normalized before comparison).
    proxied : bool | None
        The desired Cloudflare proxy status (CF only, A/AAAA/CNAME).
    """

    value: str
    ttl: int | None = None
    comment: str | None = None
    proxied: bool | None = None


@dataclass
class UpstreamResult:
    """
    Result from an upstream provider operation.

    This data class encapsulates the outcome of a DNS operation (create,
    update, delete) performed on an upstream provider.

    Attributes
    ----------
    success : bool
        Whether the operation was successful.
    action : str
        The action taken: "created", "updated", "deleted", or "nochange".
    message : str
        Human-readable message describing the result.
    record_id : str | None
        The DNS record ID from the provider.
    zone_id : str | None
        The zone ID (Cloudflare specific).
    request_id : str | None
        The request ID from the provider API.
    previous_value : str | None
        The previous record value (for action="updated").
    http_status : int | None
        The HTTP status code from the upstream API.
    raw_status : str | None
        The raw status string from the provider.
    extra : dict[str, str] | None
        Additional provider-specific metadata.
    warnings : list[WarningModel]
        List of non-critical warnings generated during the operation.
    """

    success: bool
    action: str
    message: str
    record_id: str | None = None
    zone_id: str | None = None
    request_id: str | None = None
    previous_value: str | None = None
    http_status: int | None = None
    raw_status: str | None = None
    extra: dict[str, str] | None = None
    warnings: list[WarningModel] = field(default_factory=list)  # type: ignore[assignment]
