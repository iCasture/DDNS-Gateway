"""Tests for normalization module."""

from __future__ import annotations

import pytest

from ddns_gateway.normalize import (
    NormalizeError,
    comments_equal,
    compute_dedupe_key,
    normalize_comment,
    normalize_record,
    normalize_ttl,
    normalize_upstream_value,
    normalize_value,
    normalize_zone,
)


class TestNormalizeZone:
    """Tests for normalize_zone function."""

    def test_basic_zone(self):
        assert normalize_zone("example.com") == "example.com"
        assert normalize_zone("EXAMPLE.COM") == "example.com"
        assert normalize_zone("Example.Com") == "example.com"

    def test_trailing_dot_removed(self):
        assert normalize_zone("example.com.") == "example.com"

    def test_url_decoded(self):
        assert normalize_zone("example%2Ecom") == "example.com"

    def test_underscores_allowed(self):
        assert normalize_zone("_dmarc.example.com") == "_dmarc.example.com"

    def test_hyphens_allowed(self):
        assert normalize_zone("my-domain.example.com") == "my-domain.example.com"

    def test_empty_zone_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_zone("")
        assert exc_info.value.code == "INVALID_ZONE_FORMAT"
        assert exc_info.value.field == "zone"

    def test_at_in_zone_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_zone("@.example.com")
        assert exc_info.value.code == "INVALID_ZONE_FORMAT"

    def test_empty_labels_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_zone("example..com")
        assert exc_info.value.code == "INVALID_ZONE_FORMAT"

    def test_leading_dot_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_zone(".example.com")
        assert exc_info.value.code == "INVALID_ZONE_FORMAT"

    def test_invalid_chars_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_zone("example!.com")
        assert exc_info.value.code == "INVALID_ZONE_FORMAT"


class TestNormalizeRecord:
    """Tests for normalize_record function."""

    def test_basic_record(self):
        assert normalize_record("home") == "home"
        assert normalize_record("HOME") == "home"
        assert normalize_record("www") == "www"

    def test_at_symbol(self):
        assert normalize_record("@") == "@"

    def test_wildcard(self):
        assert normalize_record("*") == "*"
        assert normalize_record("*.sub") == "*.sub"

    def test_subdomain(self):
        assert normalize_record("a.b.c") == "a.b.c"

    def test_underscores_allowed(self):
        assert normalize_record("_acme-challenge") == "_acme-challenge"

    def test_trailing_dot_removed(self):
        assert normalize_record("home.") == "home"

    def test_empty_record_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_record("")
        assert exc_info.value.code == "INVALID_RECORD_FORMAT"
        assert exc_info.value.field == "record"

    def test_invalid_wildcard_raises(self):
        # Wildcard in the middle
        with pytest.raises(NormalizeError) as exc_info:
            normalize_record("foo.*.bar")
        assert exc_info.value.code == "INVALID_RECORD_FORMAT"

    def test_mixed_wildcard_raises(self):
        # Wildcard mixed with other chars
        with pytest.raises(NormalizeError) as exc_info:
            normalize_record("a*b")
        assert exc_info.value.code == "INVALID_RECORD_FORMAT"

    def test_trailing_wildcard_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_record("sub.*")
        assert exc_info.value.code == "INVALID_RECORD_FORMAT"

    def test_empty_labels_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_record("a..b")
        assert exc_info.value.code == "INVALID_RECORD_FORMAT"


class TestNormalizeValue:
    """Tests for normalize_value function."""

    def test_ipv4_valid(self):
        assert normalize_value("1.2.3.4", "A") == "1.2.3.4"
        assert normalize_value("  1.2.3.4  ", "A") == "1.2.3.4"
        assert normalize_value("192.168.1.1", "A") == "192.168.1.1"

    def test_ipv4_invalid_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_value("256.1.1.1", "A")
        assert exc_info.value.code == "INVALID_IP_ADDRESS"

        with pytest.raises(NormalizeError) as exc_info:
            normalize_value("not.an.ip", "A")
        assert exc_info.value.code == "INVALID_IP_ADDRESS"

    def test_ipv6_valid(self):
        # Full format
        assert (
            normalize_value("2001:0db8:0000:0000:0000:0000:0000:0001", "AAAA")
            == "2001:db8::1"
        )
        # Compressed format
        assert normalize_value("2001:db8::1", "AAAA") == "2001:db8::1"
        # Uppercase
        assert normalize_value("2001:DB8::1", "AAAA") == "2001:db8::1"

    def test_ipv6_invalid_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_value("not:an:ipv6", "AAAA")
        assert exc_info.value.code == "INVALID_IP_ADDRESS"

    def test_cname_valid(self):
        assert normalize_value("target.example.com", "CNAME") == "target.example.com"
        assert normalize_value("TARGET.EXAMPLE.COM", "CNAME") == "target.example.com"
        assert normalize_value("target.example.com.", "CNAME") == "target.example.com"

    def test_cname_with_underscore(self):
        assert normalize_value("_dmarc.example.com", "CNAME") == "_dmarc.example.com"

    def test_cname_empty_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_value("", "CNAME")
        assert exc_info.value.code == "VALIDATION_ERROR"

    def test_txt_valid(self):
        assert normalize_value("some text value", "TXT") == "some text value"
        assert (
            normalize_value("v=spf1 include:_spf.google.com ~all", "TXT")
            == "v=spf1 include:_spf.google.com ~all"
        )

    def test_txt_too_long_raises(self):
        long_value = "x" * 1025
        with pytest.raises(NormalizeError) as exc_info:
            normalize_value(long_value, "TXT")
        assert exc_info.value.code == "TXT_VALUE_TOO_LONG"

    def test_empty_value_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_value("", "A")
        assert exc_info.value.code == "VALIDATION_ERROR"


class TestNormalizeTtl:
    """Tests for normalize_ttl function."""

    def test_int_valid(self):
        assert normalize_ttl(300) == 300
        assert normalize_ttl(0) == 0

    def test_string_valid(self):
        assert normalize_ttl("300") == 300
        assert normalize_ttl("  300  ") == 300

    def test_none_returns_none(self):
        assert normalize_ttl(None) is None

    def test_empty_string_returns_none(self):
        assert normalize_ttl("") is None
        assert normalize_ttl("   ") is None

    def test_negative_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_ttl(-1)
        assert exc_info.value.code == "VALIDATION_ERROR"

    def test_invalid_string_raises(self):
        with pytest.raises(NormalizeError) as exc_info:
            normalize_ttl("not-a-number")
        assert exc_info.value.code == "VALIDATION_ERROR"


class TestNormalizeComment:
    """Tests for normalize_comment function."""

    def test_basic_comment(self):
        assert normalize_comment("hello") == "hello"
        assert normalize_comment("  hello  ") == "hello"

    def test_none_returns_none(self):
        assert normalize_comment(None) is None

    def test_empty_returns_none(self):
        assert normalize_comment("") is None
        assert normalize_comment("   ") is None

    def test_preserves_internal_whitespace(self):
        assert normalize_comment("hello  world") == "hello  world"

    def test_preserves_case(self):
        assert normalize_comment("Hello World") == "Hello World"


class TestCommentsEqual:
    """Tests for comments_equal function."""

    def test_equal_comments(self):
        assert comments_equal("hello", "hello") is True
        assert comments_equal("  hello  ", "hello") is True
        assert comments_equal(None, None) is True
        assert comments_equal("", None) is True
        assert comments_equal(None, "") is True

    def test_unequal_comments(self):
        assert comments_equal("hello", "world") is False
        assert comments_equal("hello", None) is False
        assert comments_equal(None, "hello") is False


class TestNormalizeUpstreamValue:
    """Tests for normalize_upstream_value function."""

    def test_ipv4(self):
        assert normalize_upstream_value("1.2.3.4", "A") == "1.2.3.4"
        assert normalize_upstream_value("  1.2.3.4  ", "A") == "1.2.3.4"

    def test_ipv6_compressed(self):
        assert normalize_upstream_value("2001:0db8::1", "AAAA") == "2001:db8::1"
        assert normalize_upstream_value("2001:DB8::1", "AAAA") == "2001:db8::1"

    def test_cname(self):
        assert (
            normalize_upstream_value("target.example.com.", "CNAME")
            == "target.example.com"
        )
        assert (
            normalize_upstream_value("TARGET.EXAMPLE.COM", "CNAME")
            == "target.example.com"
        )

    def test_txt(self):
        assert normalize_upstream_value("  some text  ", "TXT") == "some text"

    def test_empty_string(self):
        assert normalize_upstream_value("", "A") == ""


class TestComputeDedupeKey:
    """Tests for compute_dedupe_key function."""

    def test_same_inputs_same_key(self):
        key1 = compute_dedupe_key(
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment="test",
            proxied=False,
        )
        key2 = compute_dedupe_key(
            provider="cloudflare",
            zone="example.com",
            record_type="A",
            record="home",
            value="1.2.3.4",
            ttl=300,
            comment="test",
            proxied=False,
        )
        assert key1 == key2

    def test_different_value_different_key(self):
        key1 = compute_dedupe_key(
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
        key1 = compute_dedupe_key(
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
        key = compute_dedupe_key(
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
