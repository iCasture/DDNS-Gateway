"""
Dedupe cache module for DDNS Gateway.

This module provides request deduplication caching to avoid redundant
upstream API calls for identical requests within a configurable time window.

Cache Pollution Warning
-----------------------
The cache stores immutable `CachedResponseBase` objects. When building
responses from cache hits, we use shallow copy (`{**base_dict, ...}`).

CRITICAL: Never modify nested objects from the cached base directly.
If you need to modify a nested field, you MUST copy that specific subtree first.
Violating this will pollute the cache and cause unpredictable behavior.

Safe pattern::

    # OK: Override top-level keys, don't modify nested objects
    resp = {**base_dict, "action": "deduped", "meta": new_meta}

    # DANGER: Modifying nested object pollutes cache!
    resp = {**base_dict}
    resp["result"]["effective"]["value"] = "new"  # BAD!

    # Safe if needed: Copy the nested object first
    result_copy = {**base_dict["result"]}
    result_copy["effective"] = {**result_copy["effective"], "value": "new"}
    resp = {**base_dict, "result": result_copy}  # OK
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(slots=True, frozen=True)
class CachedResponseBase:
    """
    Immutable cached response base.

    Contains all stable response fields that don't change between cache hits.
    Frozen to prevent accidental mutation.

    When responding to a cache hit, override:
    - action -> "deduped" (not original_action)
    - upstream_called -> False (cache hit means no upstream API call at all)

    And generate fresh:
    - meta.request_id
    - meta.timestamp
    - meta.dedupe.hit = True

    Attributes
    ----------
    status : str
        Response status: "success" or "error".
    original_action : str
        The original action from upstream: "created", "updated", "unchanged", "deleted".
    provider : str
        Provider name (lowercase).
    zone : str
        Normalized zone.
    record_type : str
        Record type (uppercase).
    record : str
        Normalized record name.
    record_id : str | None
        Upstream record ID.
    zone_id : str | None
        Upstream zone ID (Cloudflare only).
    value : str
        Effective value.
    ttl : int | None
        Effective TTL.
    comment : str | None
        Effective comment.
    proxied : bool | None
        Effective proxied status (Cloudflare only).
    previous_value : str | None
        Previous value if this was an update.
    warnings : tuple
        Warnings from upstream call (tuple for immutability).
    """

    # Response status
    status: str  # "success" | "error"
    original_action: str  # "created" | "updated" | "unchanged" | "deleted"

    # Record identity
    provider: str
    zone: str
    record_type: str
    record: str

    # Upstream result
    record_id: str | None
    zone_id: str | None

    # Effective values
    value: str
    ttl: int | None
    comment: str | None
    proxied: bool | None
    previous_value: str | None

    # Warnings from upstream (immutable tuple)
    warnings: tuple = field(default_factory=tuple)  # type: ignore[assignment]


@dataclass(slots=True)
class DedupeEntry:
    """
    Cached dedupe entry.

    Attributes
    ----------
    key_hash : str
        SHA256 of canonical request.
    timestamp : float
        Unix timestamp when entry was created.
    base : CachedResponseBase | None
        The cached response base (immutable). None when in_flight.
    in_flight : bool
        Flag for Singleflight. True = request in progress.
    in_flight_started_at : float | None
        Timestamp when in_flight was set. Used for lease expiration.
    _event : asyncio.Event | None
        Event for waiters to wait on. Set when result is ready.
    """

    key_hash: str
    timestamp: float
    base: CachedResponseBase | None = None
    in_flight: bool = False
    in_flight_started_at: float | None = None
    lease_sec: float | None = None  # Original lease duration for this entry
    _event: asyncio.Event | None = field(default=None, repr=False)


# =============================================================================
# Dedupe Cache
# =============================================================================


class DedupeCache:
    """
    In-memory LRU cache for request deduplication.

    Thread-safe via asyncio.Lock for concurrent access.
    Implements LRU eviction when max_entries is exceeded.

    Parameters
    ----------
    max_entries : int
        Maximum number of cache entries.
    window_seconds : int
        Time window for cache validity (seconds).
    """

    def __init__(
        self,
        max_entries: int = 1000,
        window_seconds: int = 300,
    ) -> None:
        """Initialize the cache."""
        self._entries: OrderedDict[str, DedupeEntry] = OrderedDict()
        self._max_entries = max_entries
        self._window_seconds = window_seconds
        self._lock = asyncio.Lock()

    @property
    def window_seconds(self) -> int:
        """Get the window seconds configuration."""
        return self._window_seconds

    @property
    def max_entries(self) -> int:
        """Get the max entries configuration."""
        return self._max_entries

    # =========================================================================
    # Core Operations
    # =========================================================================

    async def get(self, key_hash: str) -> DedupeEntry | None:
        """
        Get a valid (non-expired) entry from cache.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.

        Returns
        -------
        DedupeEntry | None
            The cached entry if valid, None otherwise.

        Notes
        -----
        - Returns None if entry doesn't exist
        - Returns None if entry is expired (beyond window_seconds)
        - Returns None if entry is in-flight (Stage 4.2)
        - Moves accessed entry to end (LRU behavior)
        """
        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry is None:
                return None

            # Check expiration
            now = time.time()
            if now - entry.timestamp > self._window_seconds:
                # Expired, remove it
                del self._entries[key_hash]
                logger.debug(
                    '[dedupe] Entry expired: "%s" (Age: "%.1fs") ...',
                    key_hash[:16],
                    now - entry.timestamp,
                )
                return None

            # Skip in-flight entries (Stage 4.2)
            if entry.in_flight:
                logger.debug('[dedupe] Entry in-flight: "%s" ...', key_hash[:16])
                return None

            # LRU: move to end
            self._entries.move_to_end(key_hash)

            logger.debug(
                '[dedupe] Cache hit: "%s" (Age: "%.1fs") ...',
                key_hash[:16],
                now - entry.timestamp,
            )
            return entry

    async def set(
        self,
        key_hash: str,
        base: CachedResponseBase,
    ) -> DedupeEntry:
        """
        Set an entry in cache.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.
        base : CachedResponseBase
            The immutable response base to cache.

        Returns
        -------
        DedupeEntry
            The newly created entry.

        Notes
        -----
        - Creates entry with current timestamp
        - Evicts oldest entry if at max_entries
        - If replacing an in-flight entry, notifies waiters
        """
        event_to_set: asyncio.Event | None = None

        async with self._lock:
            now = time.time()

            # Grab event from existing in-flight entry (if any)
            existing = self._entries.get(key_hash)
            if existing is not None and existing.in_flight:
                event_to_set = existing._event  # noqa: SLF001

            entry = DedupeEntry(
                key_hash=key_hash,
                timestamp=now,
                base=base,
                in_flight=False,
                in_flight_started_at=None,
                _event=None,
            )

            # Evict oldest entries if at capacity
            while len(self._entries) >= self._max_entries:
                oldest_key, oldest_entry = self._entries.popitem(last=False)
                logger.debug(
                    '[dedupe] Evicted oldest: "%s" (Age: "%.1fs") ...',
                    oldest_key[:16],
                    now - oldest_entry.timestamp,
                )

            self._entries[key_hash] = entry
            self._entries.move_to_end(key_hash)

            logger.debug(
                '[dedupe] Cache set: "%s" (Size: "%d / %d") ...',
                key_hash[:16],
                len(self._entries),
                self._max_entries,
            )

        # Notify waiters AFTER releasing lock
        if event_to_set is not None:
            event_to_set.set()

        return entry

    async def delete(self, key_hash: str) -> bool:
        """
        Delete an entry from cache.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.

        Returns
        -------
        bool
            True if entry existed and was deleted, False otherwise.
        """
        async with self._lock:
            if key_hash in self._entries:
                del self._entries[key_hash]
                logger.debug('[dedupe] Deleted: "%s" ...', key_hash[:16])
                return True
            return False

    async def cleanup(self) -> int:
        """
        Remove all expired entries.

        Returns
        -------
        int
            Number of entries removed.
        """
        async with self._lock:
            now = time.time()
            expired = [
                k
                for k, v in self._entries.items()
                if now - v.timestamp > self._window_seconds
            ]
            for k in expired:
                del self._entries[k]

            if expired:
                logger.debug(
                    "[dedupe] Cleanup removed %d expired entries ...",
                    len(expired),
                )
            return len(expired)

    async def clear(self) -> int:
        """
        Clear all entries.

        Returns
        -------
        int
            Number of entries removed.
        """
        async with self._lock:
            count = len(self._entries)
            self._entries.clear()
            logger.debug("[dedupe] Cleared all %d entries ...", count)
            return count

    async def size(self) -> int:
        """
        Get current number of entries.

        Returns
        -------
        int
            Current cache size.
        """
        async with self._lock:
            return len(self._entries)

    # =========================================================================
    # Singleflight Interface (Stage 4.2)
    # =========================================================================

    async def mark_in_flight(
        self,
        key_hash: str,
        lease_sec: float = 60.0,
    ) -> bool:
        """
        Mark a key as in-flight (this request is the leader).

        If an in-flight entry exists and its lease hasn't expired, returns False
        (another leader is processing). If lease has expired, allows takeover.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.
        lease_sec : float
            Lease duration in seconds. If in-flight entry is older than this,
            allow takeover.

        Returns
        -------
        bool
            True if successfully marked as leader.
            False if already in-flight by another leader (should wait).
        """
        async with self._lock:
            entry = self._entries.get(key_hash)
            now = time.time()

            # Case 1: Entry exists and is in-flight
            if entry is not None and entry.in_flight:
                # Check lease expiration using ENTRY's lease_sec
                if (
                    entry.in_flight_started_at is not None
                    and entry.lease_sec is not None
                ):
                    age = now - entry.in_flight_started_at
                    if age < entry.lease_sec:
                        return False  # Lease still valid, cannot takeover
                    # Lease expired, allow takeover
                    logger.debug(
                        '[dedupe] Lease expired for "%s" (Age: "%.1fs" > "%.1fs"), takeover ...',
                        key_hash[:16],
                        age,
                        lease_sec,
                    )
                else:
                    # Fallback: no timestamp, check by entry timestamp
                    return False

            # Case 2: Valid cache exists (not expired)
            if entry is not None and not entry.in_flight:
                if now - entry.timestamp <= self._window_seconds:
                    return False  # Cache hit, no need to be leader

            # Create in-flight placeholder
            event = asyncio.Event()
            self._entries[key_hash] = DedupeEntry(
                key_hash=key_hash,
                timestamp=now,
                base=None,  # No result yet
                in_flight=True,
                in_flight_started_at=now,
                lease_sec=lease_sec,  # Record lease for takeover check
                _event=event,
            )
            self._entries.move_to_end(key_hash)
            logger.debug('[dedupe] Marked in-flight: "%s" ...', key_hash[:16])
            return True

    async def clear_in_flight(self, key_hash: str) -> None:
        """
        Clear the in-flight flag without storing a result.

        Use when the leader request failed and there's no result to cache.
        All waiters will be notified and will get None from wait_for_result.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.
        """
        event_to_set: asyncio.Event | None = None

        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry is None or not entry.in_flight:
                return

            event_to_set = entry._event  # noqa: SLF001
            del self._entries[key_hash]
            logger.debug('[dedupe] Cleared in-flight: "%s" ...', key_hash[:16])

        # Notify waiters AFTER releasing lock (they'll get None)
        if event_to_set is not None:
            event_to_set.set()

    async def wait_for_result(
        self,
        key_hash: str,
        wait_timeout_sec: float = 30.0,
    ) -> DedupeEntry | None:
        """
        Wait for an in-flight request to complete.

        Returns the result if it becomes available within the timeout.
        Returns None on timeout - the caller should return an error, NOT retry.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.
        wait_timeout_sec : float
            Maximum time to wait in seconds.

        Returns
        -------
        DedupeEntry | None
            The result entry if available, None on timeout or failure.
        """
        # Get event under lock
        event: asyncio.Event | None = None
        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry is None:
                return None
            if not entry.in_flight:
                # Already ready (race condition - result arrived)
                now = time.time()
                if now - entry.timestamp <= self._window_seconds and entry.base:
                    return entry
                return None
            event = entry._event  # noqa: SLF001

        if event is None:
            return None

        # Wait outside lock to avoid deadlock
        try:
            await asyncio.wait_for(event.wait(), timeout=wait_timeout_sec)
        except TimeoutError:
            logger.debug(
                '[dedupe] Wait timeout for "%s" (Timeout: "%.1fs") ...',
                key_hash[:16],
                wait_timeout_sec,
            )
            return None

        # Re-check for result after event is set
        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry is None or entry.in_flight or entry.base is None:
                return None
            logger.debug('[dedupe] Wait succeeded for "%s" ...', key_hash[:16])
            return entry

    # =========================================================================
    # Persistence Interface (Stage 4.3 - Placeholder)
    # =========================================================================

    async def to_list(self) -> list[DedupeEntry]:
        """
        Export all valid (non-expired) entries as a list.

        Reserved for Stage 4.3 SQLite persistence.

        Returns
        -------
        list[DedupeEntry]
            List of valid entries.
        """
        async with self._lock:
            now = time.time()
            return [
                entry
                for entry in self._entries.values()
                if now - entry.timestamp <= self._window_seconds
            ]

    async def load(
        self,
        entries: list[DedupeEntry],
        *,
        replace: bool = False,
    ) -> int:
        """
        Load entries from external source.

        Reserved for Stage 4.3 SQLite persistence.

        Parameters
        ----------
        entries : list[DedupeEntry]
            Entries to load.
        replace : bool
            If True, clear existing entries first.
            If False, merge (newer timestamp wins on conflict).

        Returns
        -------
        int
            Number of entries loaded.
        """
        async with self._lock:
            if replace:
                self._entries.clear()

            now = time.time()
            loaded = 0

            for entry in entries:
                # Skip expired entries
                if now - entry.timestamp > self._window_seconds:
                    continue

                key = entry.key_hash
                existing = self._entries.get(key)

                # Newer wins on conflict
                if existing is None or entry.timestamp > existing.timestamp:
                    self._entries[key] = entry
                    loaded += 1

            logger.debug("[dedupe] Loaded %d entries from persistence ...", loaded)
            return loaded


# =============================================================================
# Helper Functions
# =============================================================================


def compute_dedupe_key(
    operation: str,
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    value: str | None,
    ttl: int | None,
    comment: str | None,
    proxied: bool | None,  # noqa: FBT001
) -> str:
    """
    Compute SHA256 hash of canonical request for deduplication.

    Parameters
    ----------
    operation : str
        Operation type: "upsert" or "delete".
    provider : str
        Provider name (lowercase, normalized).
    zone : str
        Zone name (normalized).
    record_type : str
        Record type (uppercase).
    record : str
        Record name (normalized).
    value : str | None
        Record value (normalized). None for delete operations.
    ttl : int | None
        TTL value. None for delete operations.
    comment : str | None
        Comment (normalized). None for delete operations.
    proxied : bool | None
        Proxied status (Cloudflare only). None for delete or non-CF.

    Returns
    -------
    str
        SHA256 hex digest.

    Notes
    -----
    - `operation` separates upsert/delete key spaces
    - All inputs should be pre-normalized
    - format/Accept header do NOT participate in key calculation
    - For DELETE: value/ttl/comment/proxied should all be None
    - `proxied` should be None for non-Cloudflare or TXT records.
    """
    canonical = {
        "op": operation,
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


def build_deduped_response(
    entry: DedupeEntry,
    window_seconds: int,
) -> dict:
    """
    Build a response dict for dedupe cache hit.

    Creates a new response dict from the cached base, overriding:
    - action -> "deduped"
    - upstream_called -> False (no upstream call, served from cache)
    - meta -> fresh (new request_id, timestamp, dedupe.hit=True)

    CACHE POLLUTION WARNING:
    This function returns a dict that shares nested objects with the cached base.
    DO NOT modify any nested objects in the returned dict. If you need to modify
    nested fields, copy them first. See module docstring for safe patterns.

    Parameters
    ----------
    entry : DedupeEntry
        The cached entry.
    window_seconds : int
        The dedupe window for meta info.

    Returns
    -------
    dict
        Response dict suitable for converting to DDNSResponse.
        The caller should construct DDNSResponse from this.
    """
    base = entry.base
    if base is None:
        msg = "Cannot build deduped response from in-flight entry (base is None)"
        raise ValueError(msg)

    # Build fresh meta (these are always new, never cached)
    fresh_meta = {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "dedupe": {
            "hit": True,
            "window_sec": window_seconds,
        },
    }

    # Build result info (read-only from cache, do not modify!)
    result_info = None
    if base.record_id is not None or base.value:
        effective = {
            "value": base.value,
            "ttl": base.ttl,
            "comment": base.comment,
            "proxied": base.proxied,
        }
        upstream = None
        if base.record_id:
            upstream = {
                "record_id": base.record_id,
                "zone_id": base.zone_id,
            }
        result_info = {
            "effective": effective,
            "upstream": upstream,
            "previous_value": base.previous_value,
        }

    # Build record info (read-only from cache)
    record_info = {
        "zone": base.zone,
        "type": base.record_type,
        "name": base.record,
    }

    # Add DEDUPE_HIT_SHORTCIRCUIT warning to indicate cache hit
    # This allows RouterOS scripts to distinguish between "no upstream call"
    # (deduped) and "upstream called but no change" (unchanged).
    # Both the action field (action="deduped" vs action="unchanged") and this
    # warning code can be used for machine-readable detection.
    # Convert all warnings to dict format for consistency
    warnings_list: list[dict] = []
    for w in base.warnings:
        if isinstance(w, dict):
            warnings_list.append(w)
        # Convert WarningModel (Pydantic) to dict
        # Try model_dump() first (Pydantic v2), then dict() (Pydantic v1)
        elif hasattr(w, "model_dump"):
            warnings_list.append(w.model_dump(exclude_none=True))
        elif hasattr(w, "dict"):
            warnings_list.append(w.dict(exclude_none=True))
        else:
            # Fallback: construct from attributes
            warnings_list.append(
                {
                    "code": getattr(w, "code", str(w)),
                    "message": getattr(w, "message", str(w)),
                    "field": getattr(w, "field", None),
                    "details": getattr(w, "details", None),
                },
            )

    # Add the dedupe hit warning
    warnings_list.append(
        {
            "code": "DEDUPE_HIT_SHORTCIRCUIT",
            "message": "Request was short-circuited due to deduplication cache hit. No upstream API call was made.",
            "field": "dedupe",
            "details": {
                "window_sec": window_seconds,
            },
        },
    )

    return {
        "status": base.status,
        "action": "deduped",  # Override: NOT original_action
        "upstream_called": False,  # Override: cache hit means no upstream
        "provider": base.provider,
        "record": record_info,
        "result": result_info,
        "warnings": warnings_list,
        "errors": [],
        "meta": fresh_meta,
        "debug": None,
    }


def create_cached_base(
    *,
    status: str,
    action: str,
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    record_id: str | None,
    zone_id: str | None,
    value: str,
    ttl: int | None,
    comment: str | None,
    proxied: bool | None,
    previous_value: str | None,
    warnings: list | tuple,
) -> CachedResponseBase:
    """
    Create a CachedResponseBase from service layer values.

    Called after successful upstream operation to store in cache.

    Parameters
    ----------
    status : str
        "success" or "error"
    action : str
        The original action: "created", "updated", "unchanged", "deleted"
    provider : str
        Provider name (lowercase)
    zone : str
        Normalized zone
    record_type : str
        Record type (uppercase)
    record : str
        Normalized record name
    record_id : str | None
        Upstream record ID
    zone_id : str | None
        Upstream zone ID (Cloudflare only)
    value : str
        Effective value
    ttl : int | None
        Effective TTL
    comment : str | None
        Effective comment
    proxied : bool | None
        Effective proxied (Cloudflare only)
    previous_value : str | None
        Previous value if updated
    warnings : list | tuple
        Warnings from upstream call

    Returns
    -------
    CachedResponseBase
        Immutable cached response base.
    """
    return CachedResponseBase(
        status=status,
        original_action=action,
        provider=provider,
        zone=zone,
        record_type=record_type,
        record=record,
        record_id=record_id,
        zone_id=zone_id,
        value=value,
        ttl=ttl,
        comment=comment,
        proxied=proxied,
        previous_value=previous_value,
        warnings=tuple(warnings),  # Ensure immutable
    )
