"""
Normalization module for DDNS Gateway.

This module provides functions to normalize and validate DNS record parameters
before they are processed. All normalization is done to ensure consistent
comparisons and deduplication.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import unquote

# =============================================================================
# Custom Exceptions
# =============================================================================


class NormalizeError(Exception):
    """
    Exception raised when normalization fails.

    Attributes
    ----------
    code : str
        Machine-readable error code (should match ErrorCode values).
    message : str
        Human-readable error message.
    field : str
        The field that caused the error.
    """

    def __init__(self, code: str, message: str, field: str) -> None:
        """
        Initialize a NormalizeError.

        Parameters
        ----------
        code : str
            Error code.
        message : str
            Error message.
        field : str
            Field name that caused the error.
        """
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field


# =============================================================================
# Regex Patterns
# =============================================================================

# Valid characters for zone: a-z 0-9 . - _
_ZONE_CHARSET_PATTERN = re.compile(r"^[a-z0-9.\-_]+$")

# Valid characters for record: a-z 0-9 . - _ * @
_RECORD_CHARSET_PATTERN = re.compile(r"^[a-z0-9.\-_*@]+$")

# Valid domain label (for CNAME validation)
_DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9\-_]*[a-z0-9])?$|^[a-z0-9]$")

# Maximum TXT record length in Unicode codepoints
_MAX_TXT_LENGTH = 1024


# =============================================================================
# Zone Normalization
# =============================================================================


def normalize_zone(raw: str) -> str:
    """
    Normalize zone name.

    Normalization steps:
    1. URL decode (once only, reject invalid %HH)
    2. Remove trailing dot
    3. Reject empty labels (a..b, .a, a.)
    4. Lowercase
    5. Validate charset: a-z 0-9 . - _
    6. Reject @ in zone

    Parameters
    ----------
    raw : str
        Raw zone name from user input.

    Returns
    -------
    str
        Normalized zone name.

    Raises
    ------
    NormalizeError
        If validation fails.
    """
    if not raw:
        raise NormalizeError(
            code="INVALID_ZONE_FORMAT",
            message="Zone name cannot be empty",
            field="zone",
        )

    # Step 1: URL decode (once only)
    try:
        decoded = unquote(raw, errors="strict")
    except ValueError as e:
        raise NormalizeError(
            code="INVALID_ZONE_FORMAT",
            message=f"Invalid URL encoding in zone: {e}",
            field="zone",
        ) from e

    # Step 2: Remove trailing dot
    decoded = decoded.removesuffix(".")

    # Step 3: Reject empty result or empty labels
    if not decoded:
        raise NormalizeError(
            code="INVALID_ZONE_FORMAT",
            message="Zone name cannot be empty after removing trailing dot",
            field="zone",
        )

    # Check for empty labels (consecutive dots, leading dot)
    if ".." in decoded or decoded.startswith("."):
        raise NormalizeError(
            code="INVALID_ZONE_FORMAT",
            message="Zone name contains empty labels",
            field="zone",
        )

    # Step 4: Lowercase
    normalized = decoded.lower()

    # Step 5: Validate charset
    if not _ZONE_CHARSET_PATTERN.match(normalized):
        raise NormalizeError(
            code="INVALID_ZONE_FORMAT",
            message="Zone name contains invalid characters. Allowed: a-z 0-9 . - _",
            field="zone",
        )

    # Step 6: Reject @ in zone
    if "@" in normalized:
        raise NormalizeError(
            code="INVALID_ZONE_FORMAT",
            message="Zone name cannot contain '@'. Use '@' only in the record field.",
            field="zone",
        )

    return normalized


# =============================================================================
# Record Normalization
# =============================================================================


def normalize_record(raw: str) -> str:
    """
    Normalize record name.

    Normalization steps:
    1. URL decode (once only)
    2. Remove trailing dot
    3. Reject empty labels (except for @ and *)
    4. Lowercase
    5. Validate charset: a-z 0-9 . - _ * @
    6. Validate wildcard: only * or *.xxx allowed

    Note: record is relative to zone, not a full FQDN.

    Parameters
    ----------
    raw : str
        Raw record name from user input.

    Returns
    -------
    str
        Normalized record name.

    Raises
    ------
    NormalizeError
        If validation fails.
    """
    if not raw:
        raise NormalizeError(
            code="INVALID_RECORD_FORMAT",
            message="Record name cannot be empty",
            field="record",
        )

    # Step 1: URL decode (once only)
    try:
        decoded = unquote(raw, errors="strict")
    except ValueError as e:
        raise NormalizeError(
            code="INVALID_RECORD_FORMAT",
            message=f"Invalid URL encoding in record: {e}",
            field="record",
        ) from e

    # Step 2: Remove trailing dot
    decoded = decoded.removesuffix(".")

    # Step 3: Check for empty result
    if not decoded:
        raise NormalizeError(
            code="INVALID_RECORD_FORMAT",
            message="Record name cannot be empty after removing trailing dot",
            field="record",
        )

    # Step 4: Lowercase
    normalized = decoded.lower()

    # Special cases: @ and * are valid as-is
    if normalized in {"@", "*"}:
        return normalized

    # Step 5: Validate charset
    if not _RECORD_CHARSET_PATTERN.match(normalized):
        raise NormalizeError(
            code="INVALID_RECORD_FORMAT",
            message="Record name contains invalid characters. Allowed: a-z 0-9 . - _ * @",
            field="record",
        )

    # Check for empty labels (consecutive dots, leading dot, but allow trailing
    # since we already removed it)
    if ".." in normalized or normalized.startswith("."):
        raise NormalizeError(
            code="INVALID_RECORD_FORMAT",
            message="Record name contains empty labels",
            field="record",
        )

    # Step 6: Validate wildcard usage
    if "*" in normalized:
        # Wildcard must be at the beginning, either as "*" alone or "*.something"
        if not normalized.startswith("*.") and normalized != "*":
            raise NormalizeError(
                code="INVALID_RECORD_FORMAT",
                message="Wildcard (*) must be at the beginning: either '*' or '*.subdomain'",
                field="record",
            )
        # Check for wildcard in the middle (e.g., "foo.*.bar")
        parts = normalized.split(".")
        for i, part in enumerate(parts):
            if "*" in part and i > 0:
                raise NormalizeError(
                    code="INVALID_RECORD_FORMAT",
                    message="Wildcard (*) is only allowed in the first label",
                    field="record",
                )
            if "*" in part and part != "*":
                raise NormalizeError(
                    code="INVALID_RECORD_FORMAT",
                    message="Wildcard label must be exactly '*', not mixed with other characters",
                    field="record",
                )

    return normalized


# =============================================================================
# Value Normalization
# =============================================================================


def normalize_value(raw: str, record_type: str) -> str:
    """
    Normalize record value based on type.

    - A: strip, validate with ipaddress.IPv4Address
    - AAAA: strip, validate with ipaddress.IPv6Address, compress, lowercase
    - CNAME: strip, remove trailing dot, lowercase, validate as domain
    - TXT: strip, validate length (max 1024 codepoints)

    Parameters
    ----------
    raw : str
        Raw record value.
    record_type : str
        Record type (A, AAAA, CNAME, TXT).

    Returns
    -------
    str
        Normalized value.

    Raises
    ------
    NormalizeError
        If validation fails.
    """
    if not raw:
        raise NormalizeError(
            code="VALIDATION_ERROR",
            message="Value cannot be empty",
            field="value",
        )

    value = raw.strip()

    record_type_upper = record_type.upper()

    if record_type_upper == "A":
        return _normalize_ipv4(value)
    if record_type_upper == "AAAA":
        return _normalize_ipv6(value)
    if record_type_upper == "CNAME":
        return _normalize_cname(value)
    if record_type_upper == "TXT":
        return _normalize_txt(value)

    # Unknown type - just return stripped value
    return value


def _normalize_ipv4(value: str) -> str:
    """Normalize and validate IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(value)
        return str(addr)
    except ipaddress.AddressValueError as e:
        raise NormalizeError(
            code="INVALID_IP_ADDRESS",
            message=f"Invalid IPv4 address: {value}",
            field="value",
        ) from e


def _normalize_ipv6(value: str) -> str:
    """Normalize and validate IPv6 address (compressed format, lowercase)."""
    try:
        addr = ipaddress.IPv6Address(value)
        # Use compressed format and lowercase
        return str(addr).lower()
    except ipaddress.AddressValueError as e:
        raise NormalizeError(
            code="INVALID_IP_ADDRESS",
            message=f"Invalid IPv6 address: {value}",
            field="value",
        ) from e


def _normalize_cname(value: str) -> str:
    """Normalize and validate CNAME target (domain name)."""
    # Remove trailing dot
    value = value.removesuffix(".")

    if not value:
        raise NormalizeError(
            code="INVALID_DOMAIN_FORMAT",
            message="CNAME target cannot be empty",
            field="value",
        )

    # Lowercase
    normalized = value.lower()

    # Validate as domain name
    if ".." in normalized or normalized.startswith("."):
        raise NormalizeError(
            code="INVALID_DOMAIN_FORMAT",
            message="CNAME target contains empty labels",
            field="value",
        )

    # Check each label
    labels = normalized.split(".")
    for label in labels:
        if not label:
            raise NormalizeError(
                code="INVALID_DOMAIN_FORMAT",
                message="CNAME target contains empty labels",
                field="value",
            )
        # Allow underscores for service records like _dmarc
        if not _DOMAIN_LABEL_PATTERN.match(label) and not label.startswith("_"):  # noqa: SIM102
            # More permissive check for underscore-prefixed labels
            if not re.match(r"^_[a-z0-9\-_]*$", label):
                raise NormalizeError(
                    code="INVALID_DOMAIN_FORMAT",
                    message=f"CNAME target has invalid label: {label}",
                    field="value",
                )

    return normalized


def _normalize_txt(value: str) -> str:
    """Validate TXT record value (length check only)."""
    # Count Unicode codepoints
    if len(value) > _MAX_TXT_LENGTH:
        raise NormalizeError(
            code="TXT_VALUE_TOO_LONG",
            message=f"TXT record exceeds maximum length of {_MAX_TXT_LENGTH} characters",
            field="value",
        )
    return value


# =============================================================================
# TTL Normalization
# =============================================================================


def normalize_ttl(raw: str | int | None) -> int | None:
    """
    Normalize TTL to int or None.

    - Convert string to int
    - Reject negative values
    - None means use provider default

    Parameters
    ----------
    raw : str | int | None
        Raw TTL value.

    Returns
    -------
    int | None
        Normalized TTL or None.

    Raises
    ------
    NormalizeError
        If validation fails.
    """
    if raw is None:
        return None

    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
        try:
            ttl = int(raw)
        except ValueError as e:
            raise NormalizeError(
                code="VALIDATION_ERROR",
                message=f"TTL must be a valid integer: {raw}",
                field="ttl",
            ) from e
    else:
        ttl = raw

    if ttl < 0:
        raise NormalizeError(
            code="VALIDATION_ERROR",
            message="TTL cannot be negative",
            field="ttl",
        )

    return ttl


# =============================================================================
# Comment Normalization
# =============================================================================


def normalize_comment(raw: str | None) -> str | None:
    """
    Normalize comment.

    - Strip leading/trailing whitespace
    - Empty string -> None
    - Preserve internal spacing and case

    Parameters
    ----------
    raw : str | None
        Raw comment value.

    Returns
    -------
    str | None
        Normalized comment or None.
    """
    if raw is None:
        return None

    stripped = raw.strip()
    return stripped if stripped else None


def comments_equal(a: str | None, b: str | None) -> bool:
    """
    Compare two comments for equality after normalization.

    Parameters
    ----------
    a : str | None
        First comment.
    b : str | None
        Second comment.

    Returns
    -------
    bool
        True if comments are equal after normalization.
    """
    return normalize_comment(a) == normalize_comment(b)


# =============================================================================
# Upstream Value Normalization
# =============================================================================


def normalize_upstream_value(value: str, record_type: str) -> str:
    """
    Normalize value returned from upstream for comparison.

    Same rules as normalize_value but for upstream responses.
    This ensures consistent comparison between desired and existing values.

    Parameters
    ----------
    value : str
        Value from upstream provider.
    record_type : str
        Record type (A, AAAA, CNAME, TXT).

    Returns
    -------
    str
        Normalized value.
    """
    if not value:
        return value

    record_type_upper = record_type.upper()

    if record_type_upper == "A":
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ipaddress.AddressValueError:
            return value.strip()

    if record_type_upper == "AAAA":
        try:
            return str(ipaddress.IPv6Address(value.strip())).lower()
        except ipaddress.AddressValueError:
            return value.strip().lower()

    if record_type_upper == "CNAME":
        return value.strip().lower().removesuffix(".")

    # TXT and others: just strip
    return value.strip()


# =============================================================================
# Dedupe Key Computation
# =============================================================================


def compute_dedupe_key(
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    value: str,
    ttl: int | None,
    comment: str | None,
    proxied: bool | None,  # noqa: FBT001
) -> str:
    """
    Compute SHA256 hash of canonical request for deduplication.

    All inputs should be pre-normalized.
    proxied should be None for non-CF or TXT records.

    Parameters
    ----------
    provider : str
        Provider name (lowercase).
    zone : str
        Zone name (normalized).
    record_type : str
        Record type (uppercase).
    record : str
        Record name (normalized).
    value : str
        Record value (normalized).
    ttl : int | None
        TTL value.
    comment : str | None
        Comment (normalized).
    proxied : bool | None
        Proxied status (CF only).

    Returns
    -------
    str
        SHA256 hex digest.
    """
    canonical = {
        "provider": provider,
        "zone": zone,
        "type": record_type,
        "record": record,
        "value": value,
        "ttl": ttl,
        "comment": comment,
        "proxied": proxied,
    }
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode()).hexdigest()
