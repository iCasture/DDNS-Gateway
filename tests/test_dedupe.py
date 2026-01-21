"""Tests for dedupe cache module."""

from __future__ import annotations

import asyncio
import time

import pytest

from ddns_gateway.dedupe import (
    CachedResponseBase,
    DedupeCache,
    DedupeEntry,
    compute_dedupe_key,
)

# =============================================================================
# CachedResponseBase Tests
# =============================================================================


class TestCachedResponseBase:
    """Tests for CachedResponseBase dataclass."""

    def test_create_basic(self):
        """Test creating a basic CachedResponseBase."""
        base = CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id="rec123",
            zone_id="zone456",
            value="1.2.3.4",
            ttl=300,
            comment="test",
            proxied=False,
            previous_value=None,
            warnings=(),
        )
        assert base.status == "success"
        assert base.original_action == "created"
        assert base.record_id == "rec123"

    def test_is_frozen(self):
        """Test that CachedResponseBase is immutable (frozen)."""
        base = CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id=None,
            zone_id=None,
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            previous_value=None,
            warnings=(),
        )
        with pytest.raises(AttributeError):
            base.value = "5.6.7.8"  # type: ignore[misc]


# =============================================================================
# DedupeEntry Tests
# =============================================================================


class TestDedupeEntry:
    """Tests for DedupeEntry dataclass."""

    def test_create_entry(self):
        """Test creating a DedupeEntry."""
        base = CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id=None,
            zone_id=None,
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            previous_value=None,
            warnings=(),
        )
        entry = DedupeEntry(
            key_hash="abc123",
            timestamp=time.time(),
            base=base,
        )
        assert entry.key_hash == "abc123"
        assert entry.in_flight is False

    def test_in_flight_default_false(self):
        """Test that in_flight defaults to False."""
        base = CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id=None,
            zone_id=None,
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            previous_value=None,
            warnings=(),
        )
        entry = DedupeEntry(
            key_hash="abc123",
            timestamp=time.time(),
            base=base,
        )
        assert entry.in_flight is False


# =============================================================================
# DedupeCache Tests
# =============================================================================


class TestDedupeCache:
    """Tests for DedupeCache class."""

    @pytest.fixture
    def sample_base(self) -> CachedResponseBase:
        """Create a sample CachedResponseBase for testing."""
        return CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id="rec123",
            zone_id="zone456",
            value="1.2.3.4",
            ttl=300,
            comment="test",
            proxied=False,
            previous_value=None,
            warnings=(),
        )

    @pytest.mark.asyncio
    async def test_set_and_get(self, sample_base: CachedResponseBase):
        """Test setting and getting a cache entry."""
        cache = DedupeCache(max_entries=10, window_seconds=300)

        # Set entry
        entry = await cache.set("key1", sample_base)
        assert entry.key_hash == "key1"
        assert entry.base is sample_base

        # Get entry
        retrieved = await cache.get("key1")
        assert retrieved is not None
        assert retrieved.key_hash == "key1"
        assert retrieved.base.value == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self):
        """Test that getting a non-existent key returns None."""
        cache = DedupeCache()
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_expiration(self, sample_base: CachedResponseBase):
        """Test that expired entries are not returned."""
        cache = DedupeCache(max_entries=10, window_seconds=1)

        await cache.set("key1", sample_base)

        # Should exist immediately
        assert await cache.get("key1") is not None

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired now
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_lru_eviction(self, sample_base: CachedResponseBase):
        """Test LRU eviction when cache is full."""
        cache = DedupeCache(max_entries=3, window_seconds=300)

        # Fill cache
        await cache.set("key1", sample_base)
        await cache.set("key2", sample_base)
        await cache.set("key3", sample_base)

        # Verify all exist
        assert await cache.size() == 3

        # Add one more, should evict oldest (key1)
        await cache.set("key4", sample_base)

        assert await cache.size() == 3
        assert await cache.get("key1") is None  # Evicted
        assert await cache.get("key2") is not None
        assert await cache.get("key3") is not None
        assert await cache.get("key4") is not None

    @pytest.mark.asyncio
    async def test_lru_access_moves_to_end(self, sample_base: CachedResponseBase):
        """Test that accessing an entry moves it to end (LRU behavior)."""
        cache = DedupeCache(max_entries=3, window_seconds=300)

        await cache.set("key1", sample_base)
        await cache.set("key2", sample_base)
        await cache.set("key3", sample_base)

        # Access key1 to move it to end
        await cache.get("key1")

        # Now add key4, should evict key2 (oldest after key1 was accessed)
        await cache.set("key4", sample_base)

        assert await cache.get("key1") is not None  # Was accessed, not evicted
        assert await cache.get("key2") is None  # Was oldest, evicted
        assert await cache.get("key3") is not None
        assert await cache.get("key4") is not None

    @pytest.mark.asyncio
    async def test_delete(self, sample_base: CachedResponseBase):
        """Test deleting a cache entry."""
        cache = DedupeCache()

        await cache.set("key1", sample_base)
        assert await cache.get("key1") is not None

        result = await cache.delete("key1")
        assert result is True
        assert await cache.get("key1") is None

        # Delete non-existent returns False
        result = await cache.delete("key1")
        assert result is False

    @pytest.mark.asyncio
    async def test_cleanup(self, sample_base: CachedResponseBase):
        """Test cleanup removes expired entries."""
        cache = DedupeCache(max_entries=10, window_seconds=1)

        await cache.set("key1", sample_base)
        await cache.set("key2", sample_base)

        assert await cache.size() == 2

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Cleanup should remove expired entries
        removed = await cache.cleanup()
        assert removed == 2
        assert await cache.size() == 0

    @pytest.mark.asyncio
    async def test_clear(self, sample_base: CachedResponseBase):
        """Test clearing all entries."""
        cache = DedupeCache()

        await cache.set("key1", sample_base)
        await cache.set("key2", sample_base)

        assert await cache.size() == 2

        removed = await cache.clear()
        assert removed == 2
        assert await cache.size() == 0

    @pytest.mark.asyncio
    async def test_size(self, sample_base: CachedResponseBase):
        """Test size method."""
        cache = DedupeCache()

        assert await cache.size() == 0

        await cache.set("key1", sample_base)
        assert await cache.size() == 1

        await cache.set("key2", sample_base)
        assert await cache.size() == 2

    @pytest.mark.asyncio
    async def test_properties(self):
        """Test cache property accessors."""
        cache = DedupeCache(max_entries=100, window_seconds=600)
        assert cache.max_entries == 100
        assert cache.window_seconds == 600

    @pytest.mark.asyncio
    async def test_hit_count_increments(self, sample_base: CachedResponseBase):
        """Test that hit_count increments on each cache hit."""
        cache = DedupeCache()
        await cache.set("key1", sample_base)

        # First hit
        entry1 = await cache.get("key1")
        assert entry1 is not None
        assert entry1.hit_count == 1

        # Second hit
        entry2 = await cache.get("key1")
        assert entry2 is not None
        assert entry2.hit_count == 2

        # Third hit
        entry3 = await cache.get("key1")
        assert entry3 is not None
        assert entry3.hit_count == 3

    @pytest.mark.asyncio
    async def test_hit_count_starts_at_zero_after_set(self, sample_base: CachedResponseBase):
        """Test that hit_count is 0 immediately after set (before any get)."""
        cache = DedupeCache()
        entry = await cache.set("key1", sample_base)
        assert entry.hit_count == 0


# =============================================================================
# Singleflight Tests
# =============================================================================


class TestSingleflight:
    """Tests for Singleflight mechanism."""

    @pytest.fixture
    def sample_base(self) -> CachedResponseBase:
        """Create a sample CachedResponseBase for testing."""
        return CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id="rec123",
            zone_id="zone456",
            value="1.2.3.4",
            ttl=300,
            comment="test",
            proxied=False,
            previous_value=None,
            warnings=(),
        )

    @pytest.mark.asyncio
    async def test_mark_in_flight_first_request(self):
        """Test first request successfully marks as leader."""
        cache = DedupeCache()
        result = await cache.mark_in_flight("key1", lease_sec=60.0)
        assert result is True

    @pytest.mark.asyncio
    async def test_mark_in_flight_second_request_returns_false(self):
        """Test second request returns False (already in-flight)."""
        cache = DedupeCache()
        await cache.mark_in_flight("key1", lease_sec=60.0)
        result = await cache.mark_in_flight("key1", lease_sec=60.0)
        assert result is False

    @pytest.mark.asyncio
    async def test_clear_in_flight(self):
        """Test clearing in-flight flag."""
        cache = DedupeCache()
        await cache.mark_in_flight("key1", lease_sec=60.0)

        # Should clear in-flight
        await cache.clear_in_flight("key1")

        # Now we can mark again
        result = await cache.mark_in_flight("key1", lease_sec=60.0)
        assert result is True

    @pytest.mark.asyncio
    async def test_set_clears_in_flight(self, sample_base: CachedResponseBase):
        """Test that set() clears in-flight and notifies waiters."""
        cache = DedupeCache()
        await cache.mark_in_flight("key1", lease_sec=60.0)

        # Set should replace in-flight with ready entry
        await cache.set("key1", sample_base)

        # Entry should be ready (not in-flight)
        entry = await cache.get("key1")
        assert entry is not None
        assert entry.in_flight is False
        assert entry.base == sample_base

    @pytest.mark.asyncio
    async def test_wait_for_result_immediate(self, sample_base: CachedResponseBase):
        """Test wait returns immediately if result already exists."""
        cache = DedupeCache()
        await cache.set("key1", sample_base)

        # Wait should return immediately
        result = await cache.wait_for_result("key1", wait_timeout_sec=0.1)
        assert result is not None
        assert result.base == sample_base

    @pytest.mark.asyncio
    async def test_wait_for_result_timeout(self):
        """Test wait returns None on timeout."""
        cache = DedupeCache()
        await cache.mark_in_flight("key1", lease_sec=60.0)

        # Wait should timeout
        result = await cache.wait_for_result("key1", wait_timeout_sec=0.1)
        assert result is None

    @pytest.mark.asyncio
    async def test_wait_for_result_success(self, sample_base: CachedResponseBase):
        """Test wait returns result when set is called."""
        cache = DedupeCache()
        await cache.mark_in_flight("key1", lease_sec=60.0)

        async def set_after_delay():
            await asyncio.sleep(0.1)
            await cache.set("key1", sample_base)

        async def wait_for_it():
            return await cache.wait_for_result("key1", wait_timeout_sec=1.0)

        # Run both concurrently
        results = await asyncio.gather(set_after_delay(), wait_for_it())
        wait_result = results[1]

        assert wait_result is not None
        assert wait_result.base == sample_base

    @pytest.mark.asyncio
    async def test_lease_expiration_allows_takeover(self):
        """Test that expired lease allows takeover."""
        cache = DedupeCache()

        # Mark with very short lease
        await cache.mark_in_flight("key1", lease_sec=0.1)

        # Wait for lease to expire
        await asyncio.sleep(0.2)

        # Should be able to takeover
        result = await cache.mark_in_flight("key1", lease_sec=60.0)
        assert result is True

    @pytest.mark.asyncio
    async def test_valid_cache_prevents_mark(self, sample_base: CachedResponseBase):
        """Test that valid cache entry prevents marking in-flight."""
        cache = DedupeCache()

        # Set valid entry
        await cache.set("key1", sample_base)

        # Should not be able to mark (cache hit)
        result = await cache.mark_in_flight("key1", lease_sec=60.0)
        assert result is False


# =============================================================================
# compute_dedupe_key Tests (additional tests in dedupe module)
# =============================================================================


class TestComputeDedupeKeyInDedupe:
    """Additional tests for compute_dedupe_key in dedupe module."""

    def test_same_inputs_same_key(self):
        """Test that same inputs produce same key."""
        key1 = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        key2 = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        assert key1 == key2

    def test_different_value_different_key(self):
        """Test that different values produce different keys."""
        key1 = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        key2 = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="5.6.7.8",
            ttl=300,
            comment=None,
            proxied=None,
        )
        assert key1 != key2

    def test_different_ttl_different_key(self):
        """Test that different TTLs produce different keys."""
        key1 = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        key2 = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=600,
            comment=None,
            proxied=None,
        )
        assert key1 != key2

    def test_key_is_sha256_hex(self):
        """Test that the key is a valid SHA256 hex string."""
        key = compute_dedupe_key(
            operation="upsert",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        # SHA256 hex digest is 64 characters
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_delete_key_consistent(self):
        """Test that delete keys are consistent regardless of value params."""
        key1 = compute_dedupe_key(
            operation="delete",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value=None,
            ttl=None,
            comment=None,
            proxied=None,
        )
        key2 = compute_dedupe_key(
            operation="delete",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value=None,
            ttl=None,
            comment=None,
            proxied=None,
        )
        assert key1 == key2

    def test_operation_separates_keys(self):
        """Test that different operations produce different keys."""
        key_upsert = compute_dedupe_key(
            operation="upsert",
            provider="cf",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment=None,
            proxied=None,
        )
        key_delete = compute_dedupe_key(
            operation="delete",
            provider="cf",
            zone="example.com",
            record_type="A",
            record="home",
            value=None,
            ttl=None,
            comment=None,
            proxied=None,
        )
        assert key_upsert != key_delete


# =============================================================================
# get_in_flight_age Tests
# =============================================================================


class TestDedupeCacheInFlightAge:
    """Tests for get_in_flight_age method."""

    @pytest.mark.asyncio
    async def test_get_in_flight_age_returns_age(self):
        """Test that get_in_flight_age returns correct age."""
        cache = DedupeCache(max_entries=10, window_seconds=60)
        key = "test_key"

        await cache.mark_in_flight(key, lease_sec=30)
        await asyncio.sleep(0.1)

        age = await cache.get_in_flight_age(key)
        assert age is not None
        assert age >= 0.1

    @pytest.mark.asyncio
    async def test_get_in_flight_age_returns_none_for_nonexistent(self):
        """Test that get_in_flight_age returns None for nonexistent key."""
        cache = DedupeCache(max_entries=10, window_seconds=60)

        age = await cache.get_in_flight_age("nonexistent")
        assert age is None

    @pytest.mark.asyncio
    async def test_get_in_flight_age_returns_none_after_completion(self):
        """Test that get_in_flight_age returns None after in-flight is cleared."""
        cache = DedupeCache(max_entries=10, window_seconds=60)
        key = "test_key"

        await cache.mark_in_flight(key, lease_sec=30)
        await cache.clear_in_flight(key)

        age = await cache.get_in_flight_age(key)
        assert age is None

    @pytest.mark.asyncio
    async def test_get_in_flight_age_returns_none_after_set(self):
        """Test that get_in_flight_age returns None after set() is called."""
        cache = DedupeCache(max_entries=10, window_seconds=60)
        key = "test_key"

        await cache.mark_in_flight(key, lease_sec=30)

        # Set a result (simulates leader completing)
        base = CachedResponseBase(
            status="success",
            original_action="created",
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            record_id=None,
            zone_id=None,
            value="1.2.3.4",
            ttl=None,
            comment=None,
            proxied=None,
            previous_value=None,
            warnings=(),
        )
        await cache.set(key, base)

        age = await cache.get_in_flight_age(key)
        assert age is None
