"""
Tests for logging_config module.

This module tests the SensitiveFilter and SENSITIVE_PATTERNS to ensure
that sensitive information is properly masked in log messages.
"""

import logging
from typing import TYPE_CHECKING

import pytest

from ddns_gateway.logging_config import SENSITIVE_PATTERNS, SensitiveFilter

if TYPE_CHECKING:
    from collections.abc import Callable


def apply_patterns(msg: str) -> str:
    """Apply all sensitive patterns to a message."""
    result = msg
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


class TestSensitivePatterns:
    """Tests for SENSITIVE_PATTERNS regex patterns."""

    # =====================================================================
    # Authorization Bearer token tests
    # =====================================================================

    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            # Standard Bearer token - keep 6 chars
            (
                "Authorization: Bearer abc123xyz789token",
                "Authorization: Bearer abc123******",
            ),
            # Short token (less than 6 chars) - keep all available
            ("Authorization: Bearer xy", "Authorization: Bearer xy******"),
            ("Authorization: Bearer a", "Authorization: Bearer a******"),
            # Empty token
            ("Authorization: Bearer ", "Authorization: Bearer ******"),
            # Case insensitive
            (
                "authorization: bearer ABC123XYZ",
                "authorization: bearer ABC123******",
            ),
            # Multiple spaces
            (
                "Authorization:   Bearer   token123",
                "Authorization:   Bearer   token1******",
            ),
        ],
    )
    def test_authorization_bearer(self, original: str, expected: str) -> None:
        """Test Authorization Bearer token masking."""
        assert apply_patterns(original) == expected

    # =====================================================================
    # id= field tests (keep 3 chars)
    # =====================================================================

    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            # Double quotes
            ('id="abcdefghijk"', 'id="abcdef******"'),
            ('id="ab"', 'id="ab******"'),
            ('id=""', 'id="******"'),
            # Single quotes
            ("id='abcdefghijk'", "id='abcdef******'"),
            ("id='ab'", "id='ab******'"),
            # Unquoted (followed by comma or end)
            ("id=abcdefghijk,", "id=abcdef******,"),
            ("id=ab,", "id=ab******,"),
            # Case insensitive
            ('ID="USER123"', 'ID="USER12******"'),
        ],
    )
    def test_id_field(self, original: str, expected: str) -> None:
        """Test id= field masking (keeps first 6 chars)."""
        assert apply_patterns(original) == expected

    # =====================================================================
    # secret= field tests (keep first 6 chars)
    # =====================================================================

    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            # Double quotes
            ('secret="mysecretkey"', 'secret="mysecr******"'),
            ('secret=""', 'secret="******"'),
            # Single quotes
            ("secret='mysecretkey'", "secret='mysecr******'"),
            # Unquoted
            ("secret=mysecretkey,", "secret=mysecr******,"),
            ("secret=abc", "secret=abc******"),
            # Case insensitive
            ('SECRET="pass123"', 'SECRET="pass12******"'),
        ],
    )
    def test_secret_field(self, original: str, expected: str) -> None:
        """Test secret= field masking (keeps first 6 chars)."""
        assert apply_patterns(original) == expected

    # =====================================================================
    # Combined patterns tests
    # =====================================================================

    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            # Full X-Upstream-Authorization header format
            (
                'id="user123", secret="pass456"',
                'id="user12******", secret="pass45******"',
            ),
            (
                "id='AKID123456789', secret='secretkey123'",
                "id='AKID12******', secret='secret******'",
            ),
            # Real-world log line example
            (
                'Received header: X-Upstream-Authorization: ApiKey id="AKID12345", '
                'secret="mysecret"',
                'Received header: X-Upstream-Authorization: ApiKey id="AKID12******", '
                'secret="mysecr******"',
            ),
        ],
    )
    def test_combined_patterns(self, original: str, expected: str) -> None:
        """Test multiple patterns applied together."""
        assert apply_patterns(original) == expected

    # =====================================================================
    # Non-matching patterns (should not be modified)
    # =====================================================================

    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            # 1. Both Double Quotes
            (
                'id="123456789", secret="abcdefghi"',
                'id="123456******", secret="abcdef******"',
            ),
            # 2. Both Single Quotes
            (
                "id='123456789', secret='abcdefghi'",
                "id='123456******', secret='abcdef******'",
            ),
            # 3. Mixed: id Double, secret Single
            (
                "id=\"123456789\", secret='abcdefghi'",
                "id=\"123456******\", secret='abcdef******'",
            ),
            # 4. Mixed: id Single, secret Double
            (
                "id='123456789', secret=\"abcdefghi\"",
                "id='123456******', secret=\"abcdef******\"",
            ),
            # 5. Mixed: id Unquoted, secret Double
            (
                'id=123456789, secret="abcdefghi"',
                'id=123456******, secret="abcdef******"',
            ),
            # 6. Mixed: id Double, secret Unquoted
            (
                'id="123456789", secret=abcdefghi',
                'id="123456******", secret=abcdef******',
            ),
            # 7. Mixed: id Unquoted, secret Single
            (
                "id=123456789, secret='abcdefghi'",
                "id=123456******, secret='abcdef******'",
            ),
            # 8. Mixed: id Single, secret Unquoted
            (
                "id='123456789', secret=abcdefghi",
                "id='123456******', secret=abcdef******",
            ),
        ],
    )
    def test_quoting_combinations(self, original: str, expected: str) -> None:
        """Test various combinations of quoting (single, double, none) for id and secret."""
        assert apply_patterns(original) == expected

    # =====================================================================
    # Query parameter placement tests (Start, Middle, End, Combinations)
    # =====================================================================

    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            # 1. Only id, at start
            ("id=123456789&foo=bar", "id=123456******&foo=bar"),
            # 2. Only secret, at start
            ("secret=abcdefghi&foo=bar", "secret=abcdef******&foo=bar"),
            # 3. Only id, in middle
            ("foo=bar&id=123456789&baz=qux", "foo=bar&id=123456******&baz=qux"),
            # 4. Only secret, in middle
            ("foo=bar&secret=abcdefghi&baz=qux", "foo=bar&secret=abcdef******&baz=qux"),
            # 5. Only id, at end
            ("foo=bar&id=123456789", "foo=bar&id=123456******"),
            # 6. Only secret, at end
            ("foo=bar&secret=abcdefghi", "foo=bar&secret=abcdef******"),
            # 7. Both, id first, consecutive
            ("id=123456789&secret=abcdefghi", "id=123456******&secret=abcdef******"),
            # 8. Both, secret first, consecutive
            ("secret=abcdefghi&id=123456789", "secret=abcdef******&id=123456******"),
            # 9. Both, id first, separated
            (
                "id=123456789&foo=bar&secret=abcdefghi",
                "id=123456******&foo=bar&secret=abcdef******",
            ),
            # 10. Both, secret first, separated
            (
                "secret=abcdefghi&foo=bar&id=123456789",
                "secret=abcdef******&foo=bar&id=123456******",
            ),
            # 11. Complex realistic example
            (
                "GET /update?provider=cloudflare&zone=example.com&id=aabdfbzxf&secret=kjhsdfvdaflgvalkjdshviuadsb",
                "GET /update?provider=cloudflare&zone=example.com&id=aabdfb******&secret=kjhsdf******",
            ),
        ],
    )
    def test_query_param_placement(self, original: str, expected: str) -> None:
        """Test id and secret in various positions within query strings."""
        assert apply_patterns(original) == expected

    @pytest.mark.parametrize(
        "original",
        [
            "Normal log message without sensitive data",
            "identifier=abc123",  # Not 'id='
            "password=abc123",  # Not 'secret='
            "api_key=abc123",  # Not matched patterns
            "Authorization: Basic abc123",  # Not Bearer
        ],
    )
    def test_non_matching_unchanged(self, original: str) -> None:
        """Test that non-matching strings are not modified."""
        assert apply_patterns(original) == original


class TestSensitiveFilter:
    """Tests for SensitiveFilter logging filter."""

    @pytest.fixture
    def log_filter(self) -> SensitiveFilter:
        """Create a SensitiveFilter instance."""
        return SensitiveFilter()

    @pytest.fixture
    def make_record(self) -> "Callable[[str], logging.LogRecord]":
        """Create a factory for log records."""

        def _make_record(msg: str) -> logging.LogRecord:
            return logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=msg,
                args=(),
                exc_info=None,
            )

        return _make_record

    def test_filter_always_returns_true(
        self,
        log_filter: SensitiveFilter,
        make_record: "Callable[[str], logging.LogRecord]",
    ) -> None:
        """Test that filter always returns True (always logs)."""
        record = make_record("any message")
        assert log_filter.filter(record) is True

    def test_filter_masks_bearer_token(
        self,
        log_filter: SensitiveFilter,
        make_record: "Callable[[str], logging.LogRecord]",
    ) -> None:
        """Test that Bearer tokens are masked in log records."""
        record = make_record("Authorization: Bearer token123456")
        log_filter.filter(record)
        assert record.msg == "Authorization: Bearer token1******"

    def test_filter_masks_upstream_auth(
        self,
        log_filter: SensitiveFilter,
        make_record: "Callable[[str], logging.LogRecord]",
    ) -> None:
        """Test that X-Upstream-Authorization fields are masked."""
        record = make_record('ApiKey id="user123", secret="pass456"')
        log_filter.filter(record)
        assert record.msg == 'ApiKey id="user12******", secret="pass45******"'

    def test_filter_handles_empty_message(
        self,
        log_filter: SensitiveFilter,
        make_record: "Callable[[str], logging.LogRecord]",
    ) -> None:
        """Test that empty messages are handled gracefully."""
        record = make_record("")
        result = log_filter.filter(record)
        assert result is True
        assert record.msg == ""

    def test_filter_handles_none_message(
        self,
        log_filter: SensitiveFilter,
    ) -> None:
        """Test that None messages are handled gracefully."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=None,  # type: ignore[arg-type]
            args=(),
            exc_info=None,
        )
        result = log_filter.filter(record)
        assert result is True

    def test_filter_masks_dict_args(
        self,
        log_filter: SensitiveFilter,
    ) -> None:
        """Test that dict-style args are masked."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Request with token %(token)s and auth %(auth)s",
            args={
                "Authorization": "Bearer mytoken123",
                "X-Upstream-Authorization": 'ApiKey   id="user123",     secret="pass456"',
            },
            exc_info=None,
        )
        log_filter.filter(record)
        assert record.args is not None
        assert isinstance(record.args, dict)
        assert record.args["Authorization"] == "Bearer mytoke******"
        assert (
            record.args["X-Upstream-Authorization"]
            == 'ApiKey   id="user12******",     secret="pass45******"'
        )
