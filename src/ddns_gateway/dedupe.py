"""
Dedupe cache module for DDNS Gateway.

This module provides request deduplication caching to avoid redundant
upstream API calls for identical requests within a configurable time window.

Cache Key vs Cache Value
------------------------
The cache key determines whether two requests are considered "the same request",
while the cache value stores the response data to return for cache hits.

**Cache Key** (computed by `compute_dedupe_key()`):
- Includes all fields that differentiate requests
- Can include hashed sensitive data (SHA256 is irreversible)
- Fields: operation, provider, zone, record_type, record, value, ttl,
  comment, proxied, upstream_credential_hash

**Cache Value** (`CachedResponseBase`):
- Stores immutable response data for cache hits
- MUST NOT contain any sensitive information (credentials, tokens)
- Safe to return to any user with the same cache key

Fields That Participate in Cache Key
------------------------------------
| Field                      | In Key | Reason                                |
|----------------------------|--------|---------------------------------------|
| operation                  | Yes    | Separates upsert/delete               |
| provider                   | Yes    | Different providers                   |
| zone                       | Yes    | Different domains                     |
| record_type                | Yes    | Different record types                |
| record                     | Yes    | Different record names                |
| value                      | Yes    | Different values                      |
| ttl                        | Yes    | Different TTLs                        |
| comment                    | Yes    | Different comments                    |
| proxied                    | Yes    | Cloudflare proxy status               |
| upstream_credential_hash   | Yes    | Different credentials -> separate cache |
| gateway_token              | No     | Gateway auth unrelated to DNS ops     |
| Accept / format            | No     | Response format doesn't affect op     |

Upstream Credential Security
----------------------------
Upstream credentials participate in cache key via SHA256 hash:
1. The hash is irreversible, no credential leakage risk
2. Cache value (`CachedResponseBase`) stores NO credential info
3. Response (`DDNSResponse`) returns NO credential info

This ensures that:
- Users with different credentials get separate cache entries
- A user's cached error (e.g., 403) won't affect another user
- Credentials are never exposed through cache

Cache Pollution Warning
-----------------------
The cache stores immutable `CachedResponseBase` objects. When building
responses from cache hits, we use shallow copy (`{**base_dict, ...}`).

CRITICAL: Never modify nested objects from the cached base directly.
If you need to modify a nested field, you MUST copy that specific subtree first.
Violating this will pollute the cache and cause unpredictable behavior.

Safe patterns:

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
from enum import Enum
from typing import overload

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================


class WaitResult(Enum):
    """
    Result status from waiting for a singleflight leader.

    Attributes
    ----------
    COMPLETED : str
        Leader completed and cached a result. The result is available
        in the entry. Note: This indicates the leader finished processing,
        regardless of whether the upstream call succeeded or failed.
        Both success and error responses are cached and returned.
    TIMEOUT : str
        Wait timeout exceeded, leader is still processing.
    ABORTED : str
        Leader aborted without caching any result. This is rare and only
        happens in emergency situations (e.g., process shutdown, cache
        corruption recovery). Normally, errors are cached via set().
    """

    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ABORTED = "aborted"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(slots=True)
class WaitForResultOutcome:
    """
    Outcome of waiting for a singleflight result.

    Attributes
    ----------
    status : WaitResult
        The result status (COMPLETED, TIMEOUT, or ABORTED).
    entry : DedupeEntry | None
        The cache entry if status is COMPLETED, None otherwise.
    """

    status: WaitResult
    entry: DedupeEntry | None = None


@dataclass(slots=True, frozen=True)
class CachedResponseBase:
    """
    Immutable cached response base.

    Contains all stable response fields that don't change between cache hits.
    Frozen to prevent accidental mutation.

    This class supports both success and error responses:
    - For success: status="success", error_* fields are None
    - For error: status="error", error_code and error_message are set

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
        The original action from upstream: "created", "updated", "unchanged",
        "deleted", or "error" for error responses.
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
    error_code : str | None
        Error code for error responses (e.g., "UPSTREAM_AUTH_ERROR").
    error_message : str | None
        Error message for error responses.
    error_details : tuple | None
        Additional error details as tuple of (key, value) pairs for immutability.
    """

    # Response status
    status: str  # "success" | "error"
    original_action: str  # "created" | "updated" | "unchanged" | "deleted" | "error"

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

    # Error information (only set for error responses)
    error_code: str | None = None
    error_message: str | None = None
    error_details: tuple | None = None  # tuple of (key, value) pairs


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
    hit_count : int
        Cache hit count. Incremented each time this entry is retrieved via get().
        First upstream call does not count; first cache hit sets hit_count = 1.
    in_flight : bool
        Flag for Singleflight. True = request in progress.
    in_flight_started_at : float | None
        Timestamp when in_flight was set. Used for lease expiration.
    aborted : bool
        Flag indicating the leader aborted without caching a result.
        Set by clear_in_flight() (emergency use only - normally errors
        should be cached via set()). When True:
        - get() returns None (treat as cache miss)
        - mark_in_flight() allows takeover (new leader can retry)
        - wait_for_result() returns ABORTED status
    generation : int
        Generation counter for singleflight takeover protection. Incremented
        each time a new leader takes over. Used to prevent stale leaders from
        overwriting newer results after a takeover.
    _event : asyncio.Event | None
        Event for waiters to wait on. Set when result is ready.
    """

    key_hash: str
    timestamp: float
    base: CachedResponseBase | None = None
    hit_count: int = 0  # Cache hit count (incremented on each cache hit)
    in_flight: bool = False
    in_flight_started_at: float | None = None
    lease_sec: float | None = None  # Original lease duration for this entry
    aborted: bool = (
        False  # True if leader aborted without caching result (emergency use only)
    )
    generation: int = 0  # Generation counter for takeover protection
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
        - Returns None if entry has aborted=True
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

            # Skip aborted entries (treat as if not cached)
            if entry.aborted:
                logger.debug('[dedupe] Entry aborted: "%s" ...', key_hash[:16])
                return None

            # LRU: move to end
            self._entries.move_to_end(key_hash)

            # Increment hit count
            entry.hit_count += 1

            logger.debug(
                '[dedupe] Cache hit: "%s" (Age: "%.1fs", Hits: "%d") ...',
                key_hash[:16],
                now - entry.timestamp,
                entry.hit_count,
            )
            return entry

    @overload
    async def set(
        self,
        key_hash: str,
        base: CachedResponseBase,
        generation: None = None,
    ) -> DedupeEntry: ...

    @overload
    async def set(
        self,
        key_hash: str,
        base: CachedResponseBase,
        generation: int,
    ) -> DedupeEntry | None: ...

    async def set(
        self,
        key_hash: str,
        base: CachedResponseBase,
        generation: int | None = None,
    ) -> DedupeEntry | None:
        """
        Set an entry in cache.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.
        base : CachedResponseBase
            The immutable response base to cache.
        generation : int | None
            If provided, only set if current entry's generation matches.
            This prevents stale leaders from overwriting newer results.
            When None (default), always succeeds (for backwards compatibility).

        Returns
        -------
        DedupeEntry | None
            The newly created entry if set successfully.
            None only when generation is provided and doesn't match
            (stale leader rejected).

        Notes
        -----
        - Creates entry with current timestamp
        - Evicts oldest entry if at max_entries
        - If replacing an in-flight entry, notifies waiters
        """
        event_to_set: asyncio.Event | None = None

        async with self._lock:
            now = time.time()

            # Grab existing entry for generation check and event
            existing = self._entries.get(key_hash)

            # Generation validation (only when generation is provided)
            if (
                generation is not None
                and existing is not None
                and existing.generation != generation
            ):
                # Stale leader trying to overwrite newer leader's result, reject
                logger.debug(
                    '[dedupe] Stale leader rejected: "%s" (gen %d != %d) ...',
                    key_hash[:16],
                    generation,
                    existing.generation,
                )
                return None

            # Grab event from existing in-flight entry (if any)
            if existing is not None and existing.in_flight:
                event_to_set = existing._event  # noqa: SLF001

            # Preserve generation from existing entry (if same-gen leader completing)
            new_generation = existing.generation if existing else 0

            entry = DedupeEntry(
                key_hash=key_hash,
                timestamp=now,
                base=base,
                in_flight=False,
                in_flight_started_at=None,
                generation=new_generation,
                _event=None,
            )

            # Evict oldest entries if at capacity
            self._evict_overflow_unlocked()

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

    async def evict_expired(
        self,
        *,
        max_age_sec: float | None = None,
    ) -> int:
        """
        Remove entries older than max_age_sec.

        Parameters
        ----------
        max_age_sec : float | None
            Maximum age in seconds. Defaults to self._window_seconds.

        Returns
        -------
        int
            Number of entries evicted.
        """
        if max_age_sec is None:
            max_age_sec = self._window_seconds
        async with self._lock:
            now = time.time()
            expired = [
                k
                for k, v in self._entries.items()
                if now - v.timestamp > max_age_sec
            ]
            for k in expired:
                del self._entries[k]

            if expired:
                logger.debug(
                    "[dedupe] Evicted %d expired entries ...",
                    len(expired),
                )
            return len(expired)

    def _evict_overflow_unlocked(self, max_entries: int | None = None) -> int:
        """
        Evict oldest entries until size < max_entries (no lock).

        .. warning::

            This is an internal method that does NOT acquire the lock.
            It MUST only be called from within an ``async with self._lock:`` block.

            For external use, call :meth:`evict_overflow` instead, which
            automatically acquires the lock before evicting.

        This method exists because ``asyncio.Lock`` is not reentrant. Methods
        like ``set()`` that already hold the lock need to call this unlocked
        version to avoid deadlock.

        Parameters
        ----------
        max_entries : int | None
            Maximum entries to keep. Defaults to self._max_entries.

        Returns
        -------
        int
            Number of entries evicted.

        See Also
        --------
        evict_overflow : Public method that acquires lock automatically.
        """
        limit = max_entries if max_entries is not None else self._max_entries
        now = time.time()
        count = 0
        while len(self._entries) >= limit:
            oldest_key, oldest_entry = self._entries.popitem(last=False)
            count += 1
            logger.debug(
                '[dedupe] Evicted oldest: "%s" (Age: "%.1fs") ...',
                oldest_key[:16],
                now - oldest_entry.timestamp,
            )
        return count

    async def evict_overflow(
        self,
        *,
        max_entries: int | None = None,
    ) -> int:
        """
        Evict oldest entries until size < max_entries.

        Parameters
        ----------
        max_entries : int | None
            Maximum entries to keep. Defaults to self._max_entries.

        Returns
        -------
        int
            Number of entries evicted.
        """
        async with self._lock:
            return self._evict_overflow_unlocked(max_entries)

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
    ) -> tuple[bool, int]:
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
        tuple[bool, int]
            (True, generation) if successfully marked as leader.
            (False, 0) if already in-flight by another leader (should wait).
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
                        return (False, 0)  # Lease still valid, cannot takeover
                    # Lease expired, allow takeover
                    logger.debug(
                        '[dedupe] Lease expired for "%s" (Age: "%.1fs" > "%.1fs"), takeover ...',
                        key_hash[:16],
                        age,
                        lease_sec,
                    )
                    # Notify old waiters so they can wake up and check the new state
                    old_event = entry._event  # noqa: SLF001
                    if old_event is not None:
                        old_event.set()
                else:
                    # Fallback: no timestamp, check by entry timestamp
                    return (False, 0)

            # Case 2: Valid cache exists (not expired, not aborted)
            if entry is not None and not entry.in_flight:
                # aborted entries should be treated as takeover-able
                # (the previous leader aborted and cached no result)
                if entry.aborted:
                    logger.debug(
                        '[dedupe] Entry aborted, allowing takeover: "%s" ...',
                        key_hash[:16],
                    )
                    # Fall through to create new in-flight entry
                elif now - entry.timestamp <= self._window_seconds:
                    return (False, 0)  # Cache hit, no need to be leader

            # Calculate new generation (increment from existing, or start at 1)
            new_generation = (entry.generation + 1) if entry else 1

            # Create in-flight placeholder
            event = asyncio.Event()
            self._entries[key_hash] = DedupeEntry(
                key_hash=key_hash,
                timestamp=now,
                base=None,  # No result yet
                in_flight=True,
                in_flight_started_at=now,
                lease_sec=lease_sec,  # Record lease for takeover check
                generation=new_generation,
                _event=event,
            )
            self._entries.move_to_end(key_hash)
            logger.debug(
                '[dedupe] Marked in-flight: "%s" (gen=%d) ...',
                key_hash[:16],
                new_generation,
            )
            return (True, new_generation)

    async def clear_in_flight(self, key_hash: str) -> None:
        """
        Clear the in-flight flag without storing a result (emergency use only).

        .. warning::

            In normal operation, you should NOT use this method. Instead, always
            cache error results using ``set()`` with ``create_cached_error_base()``.
            This ensures that subsequent identical requests receive the cached error
            instead of retrying (which would also fail).

        This method is reserved for exceptional cases where caching any result is
        impossible or undesirable, such as:

        - Graceful shutdown: clearing in-flight entries before process exit
        - Cache corruption recovery: resetting broken entries
        - Testing: simulating edge cases

        When called, it marks the entry as ``aborted=True``. Waiters will
        receive ``WaitResult.ABORTED``, and subsequent ``mark_in_flight()``
        calls can take over as leader.

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
            # Mark as aborted instead of deleting
            entry.in_flight = False
            entry.aborted = True
            logger.debug('[dedupe] Marked aborted: "%s" ...', key_hash[:16])

        # Notify waiters AFTER releasing lock (they'll see aborted=True)
        if event_to_set is not None:
            event_to_set.set()

    async def get_in_flight_age(self, key_hash: str) -> float | None:
        """
        Get the age of an in-flight request in seconds.

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.

        Returns
        -------
        float | None
            The age in seconds if the entry exists and is in-flight, None otherwise.
        """
        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry and entry.in_flight and entry.in_flight_started_at:
                return time.time() - entry.in_flight_started_at
            return None

    async def wait_for_result(
        self,
        key_hash: str,
        wait_timeout_sec: float = 30.0,
    ) -> WaitForResultOutcome:
        """
        Wait for an in-flight request to complete.

        Returns a WaitForResultOutcome indicating:
        - COMPLETED: Leader completed, entry contains the result
        - TIMEOUT: Wait timeout exceeded, leader is still processing
        - ABORTED: Leader aborted without caching a result (via clear_in_flight),
                   or a takeover occurred and the new leader hasn't completed yet

        Parameters
        ----------
        key_hash : str
            The dedupe key hash.
        wait_timeout_sec : float
            Maximum time to wait in seconds.

        Returns
        -------
        WaitForResultOutcome
            The outcome with status and optional entry.
        """
        # Get event and initial generation under lock
        event: asyncio.Event | None = None
        initial_generation: int = 0
        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry is None:
                return WaitForResultOutcome(status=WaitResult.ABORTED)
            if not entry.in_flight:
                # Already ready (race condition - result arrived)
                now = time.time()
                if now - entry.timestamp <= self._window_seconds and entry.base:
                    return WaitForResultOutcome(
                        status=WaitResult.COMPLETED, entry=entry
                    )
                # Entry exists but no valid base - check if leader aborted
                if entry.aborted:
                    return WaitForResultOutcome(status=WaitResult.ABORTED)
                return WaitForResultOutcome(status=WaitResult.ABORTED)
            initial_generation = entry.generation
            event = entry._event  # noqa: SLF001

        if event is None:
            return WaitForResultOutcome(status=WaitResult.ABORTED)

        # Wait outside lock to avoid deadlock
        try:
            await asyncio.wait_for(event.wait(), timeout=wait_timeout_sec)
        except TimeoutError:
            logger.debug(
                '[dedupe] Wait timeout for "%s" (Timeout: "%.1fs") ...',
                key_hash[:16],
                wait_timeout_sec,
            )
            return WaitForResultOutcome(status=WaitResult.TIMEOUT)

        # Re-check for result after event is set
        async with self._lock:
            entry = self._entries.get(key_hash)
            if entry is None:
                return WaitForResultOutcome(status=WaitResult.ABORTED)

            # Check if generation changed (takeover occurred)
            if entry.generation != initial_generation:
                # Leader was taken over. Check if new leader has completed.
                logger.debug(
                    '[dedupe] Generation changed for "%s" (gen %d -> %d) ...',
                    key_hash[:16],
                    initial_generation,
                    entry.generation,
                )
                if entry.base and not entry.in_flight and not entry.aborted:
                    # New leader completed, return their result
                    return WaitForResultOutcome(
                        status=WaitResult.COMPLETED, entry=entry
                    )
                # New leader still processing or failed
                return WaitForResultOutcome(status=WaitResult.ABORTED)

            # Check if leader aborted
            if entry.aborted:
                logger.debug('[dedupe] Leader aborted for "%s" ...', key_hash[:16])
                return WaitForResultOutcome(status=WaitResult.ABORTED)

            if entry.in_flight or entry.base is None:
                return WaitForResultOutcome(status=WaitResult.ABORTED)

            logger.debug('[dedupe] Wait succeeded for "%s" ...', key_hash[:16])
            return WaitForResultOutcome(status=WaitResult.COMPLETED, entry=entry)

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
    upstream_credential_hash: str | None = None,
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
    upstream_credential_hash : str | None
        SHA256 hash of upstream credentials. Used to separate cache entries
        for different users with different credentials. This ensures:
        - User A's success won't be returned to User B with different creds
        - User A's auth error (403) won't block User B with valid creds

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
    - `upstream_credential_hash` should be computed by the caller using
      SHA256 hash of the credentials dict (JSON-serialized, sorted keys).
      The hash is irreversible, ensuring no credential leakage.
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
        "cred_hash": upstream_credential_hash,
    }
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def build_dedupe_response_dict(
    entry: DedupeEntry,
    window_seconds: int,
) -> dict:
    """
    Build a dedupe response dictionary for cache hit.

    Creates a new response dict from the cached base, overriding:
    - action -> "deduped"
    - upstream_called -> False (no upstream call, served from cache)
    - meta -> fresh (new request_id, timestamp, dedupe.hit=True)

    Supports both success and error responses:
    - For success: builds full result info with effective values
    - For error: includes error code, message, and details

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
        The caller should construct DDNSResponse from this, for example
        via ``DDNSResponse.from_dedupe_dict``.
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
            "hit_count": entry.hit_count,
        },
    }

    # Build record info (read-only from cache)
    record_info = {
        "zone": base.zone,
        "type": base.record_type,
        "name": base.record,
    }

    # Handle error responses
    if base.status == "error" and base.error_code:
        # Convert error_details tuple back to dict
        error_details_dict = None
        if base.error_details:
            error_details_dict = dict(base.error_details)

        # Build warnings list
        warnings_list: list[dict] = []
        for w in base.warnings:
            if isinstance(w, dict):
                warnings_list.append(w)
            elif hasattr(w, "model_dump"):
                warnings_list.append(w.model_dump(exclude_none=True))
            elif hasattr(w, "dict"):
                warnings_list.append(w.dict(exclude_none=True))
            else:
                warnings_list.append(
                    {
                        "code": getattr(w, "code", str(w)),
                        "message": getattr(w, "message", str(w)),
                        "field": getattr(w, "field", None),
                        "details": getattr(w, "details", None),
                    },
                )

        # Add dedupe hit warning for error responses too
        warnings_list.append(
            {
                "code": "DEDUPE_HIT_SHORTCIRCUIT",
                "message": "Request was short-circuited due to deduplication cache hit. No upstream API call was made.",
                "field": "dedupe",
                "details": {
                    "window_sec": window_seconds,
                    "cached_error": True,
                },
            },
        )

        return {
            "status": "error",
            "action": "deduped",
            "upstream_called": False,
            "provider": base.provider,
            "record": record_info,
            "result": None,
            "warnings": warnings_list,
            "errors": [
                {
                    "code": base.error_code,
                    "message": base.error_message,
                    "details": error_details_dict,
                },
            ],
            "meta": fresh_meta,
            "debug": None,
        }

    # Build result info for success responses (read-only from cache, do not modify!)
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


def create_cached_error_base(
    *,
    error_code: str,
    error_message: str,
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    error_details: dict | None = None,
    warnings: list | tuple | None = None,
) -> CachedResponseBase:
    """
    Create a CachedResponseBase for error responses.

    Error responses are cached because:
    1. Upstream API calls include automatic retry for transient errors (429, 5xx).
       By the time an error reaches here, it's either a permanent error (invalid
       credentials, permission denied) or a persistent issue (retries exhausted).
    2. Since upstream credentials are included in the cache key, caching errors
       won't affect requests from users with different credentials.
    3. This prevents redundant upstream API calls for repeated identical requests
       with the same (invalid) credentials within the cache window.

    Parameters
    ----------
    error_code : str
        The error code (e.g., "UPSTREAM_AUTH_ERROR").
    error_message : str
        Human-readable error message.
    provider : str
        Provider name (lowercase).
    zone : str
        Normalized zone.
    record_type : str
        Record type (uppercase).
    record : str
        Normalized record name.
    error_details : dict | None
        Optional additional error details.
    warnings : list | tuple | None
        Optional warnings to include.

    Returns
    -------
    CachedResponseBase
        Immutable cached error response base.
    """
    # Convert error_details dict to tuple of (key, value) pairs for immutability
    details_tuple = None
    if error_details:
        details_tuple = tuple(sorted(error_details.items()))

    return CachedResponseBase(
        status="error",
        original_action="error",
        provider=provider,
        zone=zone,
        record_type=record_type,
        record=record,
        record_id=None,
        zone_id=None,
        value="",
        ttl=None,
        comment=None,
        proxied=None,
        previous_value=None,
        warnings=tuple(warnings) if warnings else (),
        error_code=error_code,
        error_message=error_message,
        error_details=details_tuple,
    )


def compute_credential_hash(credentials: dict[str, str] | None) -> str | None:
    """
    Compute SHA256 hash of credentials for cache key.

    This function creates a deterministic hash of the credentials dict
    for use in the dedupe cache key. The hash is irreversible, ensuring
    no credential leakage through the cache.

    Parameters
    ----------
    credentials : dict[str, str] | None
        The upstream credentials (id, secret).

    Returns
    -------
    str | None
        SHA256 hex digest of the credentials, or None if no credentials.
    """
    if not credentials:
        return None
    # Sort keys for deterministic JSON
    cred_json = json.dumps(credentials, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(cred_json.encode()).hexdigest()
