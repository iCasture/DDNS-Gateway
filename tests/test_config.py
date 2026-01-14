"""Tests for configuration module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ddns_gateway.config import (
    AuthConfig,
    ConfigValidationError,
    DedupeConfig,
    DedupePersistConfig,
    HealthConfig,
    LoggingConfig,
    ResponseConfig,
    RetryConfig,
    ServerConfig,
    dict_to_config,
    load_config,
    load_config_from_file,
    merge_config,
    parse_args,
    validate_config_dict,
)


class TestServerConfig:
    """Tests for ServerConfig."""

    def test_default_values(self):
        config = ServerConfig()
        assert config.host == "127.0.0.1"
        assert config.port == 38080

    def test_custom_values(self):
        config = ServerConfig(host="127.0.0.1", port=9000)
        assert config.host == "127.0.0.1"
        assert config.port == 9000


class TestAuthConfig:
    """Tests for AuthConfig."""

    def test_default_values(self):
        config = AuthConfig()
        assert config.enabled is False
        assert config.tokens == []

    def test_with_tokens(self):
        config = AuthConfig(enabled=True, tokens=["token1", "token2"])
        assert len(config.tokens) == 2
        assert "token1" in config.tokens


class TestHealthConfig:
    """Tests for HealthConfig."""

    def test_default_values(self):
        config = HealthConfig()
        assert config.enabled is False


class TestDedupeConfig:
    """Tests for DedupeConfig."""

    def test_default_values(self):
        config = DedupeConfig()
        assert config.enabled is True
        assert config.window_seconds == 300
        assert config.max_entries == 1000

    def test_persist_defaults(self):
        config = DedupeConfig()
        assert config.persist.enabled is False
        assert config.persist.path == "./data/dedupe.db"
        assert config.persist.flush_interval_seconds == 600
        assert config.persist.flush_on_startup is True

    def test_persist_custom(self):
        persist = DedupePersistConfig(
            enabled=True,
            path="/custom/path.db",
            flush_interval_seconds=300,
            flush_on_startup=False,
        )
        config = DedupeConfig(persist=persist)
        assert config.persist.enabled is True
        assert config.persist.path == "/custom/path.db"


class TestRetryConfig:
    """Tests for RetryConfig."""

    def test_default_values(self):
        config = RetryConfig()
        assert config.enabled is True
        assert config.max_attempts == 3
        assert config.request_timeout_sec == 7.0
        assert config.base_delay_ms == 1000
        assert config.max_delay_ms == 10000
        assert config.jitter is True
        assert 429 in config.on_http_status
        assert 500 in config.on_http_status

    def test_custom_request_timeout(self):
        """Test that custom request_timeout_sec is correctly applied."""
        config = RetryConfig(request_timeout_sec=15.0)
        assert config.request_timeout_sec == 15.0

    def test_from_toml_loads_custom_timeout(self):
        """Test that request_timeout_sec loads correctly from TOML."""
        toml_content = """
[retry]
request_timeout_sec = 12.5
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            config_dict = load_config_from_file(Path(f.name))
            config = dict_to_config(config_dict)

        assert config.retry.request_timeout_sec == 12.5
        # Other values should be default
        assert config.retry.enabled is True
        assert config.retry.max_attempts == 3


class TestResponseConfig:
    """Tests for ResponseConfig."""

    def test_default_values(self):
        config = ResponseConfig()
        assert config.include_debug_info is False


class TestLoggingConfig:
    """Tests for LoggingConfig."""

    def test_default_values(self):
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.file_enabled is False
        assert config.file_path == "./logs/ddns-gateway.log"


class TestMergeConfig:
    """Tests for merge_config function."""

    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = merge_config(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"server": {"host": "127.0.0.1", "port": 38080}}
        override = {"server": {"port": 9000}}
        result = merge_config(base, override)
        assert result == {"server": {"host": "127.0.0.1", "port": 9000}}


class TestDictToConfig:
    """Tests for dict_to_config function."""

    def test_empty_dict(self):
        config = dict_to_config({})
        assert config.server.host == "127.0.0.1"
        assert config.server.port == 38080
        assert config.auth.enabled is False
        assert config.health.enabled is False

    def test_full_dict(self):
        data = {
            "server": {"host": "127.0.0.1", "port": 9000},
            "auth": {"enabled": False, "tokens": ["test"]},
            "logging": {
                "level": "DEBUG",
                "file_enabled": True,
                "file_path": "/tmp/test.log",
            },
        }
        config = dict_to_config(data)
        assert config.server.host == "127.0.0.1"
        assert config.server.port == 9000
        assert config.auth.enabled is False
        assert config.auth.tokens == ["test"]
        assert config.logging.level == "DEBUG"


class TestLoadConfigFromFile:
    """Tests for load_config_from_file function."""

    def test_load_toml_file(self):
        toml_content = """
[server]
host = "127.0.0.1"
port = 9000

[auth]
enabled = true
tokens = ["token1", "token2"]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            config_path = Path(f.name)

        try:
            data = load_config_from_file(config_path)
            assert data["server"]["host"] == "127.0.0.1"
            assert data["server"]["port"] == 9000
            assert data["auth"]["tokens"] == ["token1", "token2"]
        finally:
            config_path.unlink()


class TestParseArgs:
    """Tests for parse_args function."""

    def test_default_args(self):
        """Test that all args default to None."""
        args = parse_args([])
        assert args.config is None
        assert args.host is None
        assert args.port is None
        assert args.log_level is None

    def test_custom_args(self):
        """Test parsing custom arguments."""
        args = parse_args(
            ["--host", "127.0.0.1", "--port", "9000", "--log-level", "DEBUG"],
        )
        assert args.host == "127.0.0.1"
        assert args.port == 9000
        assert args.log_level == "DEBUG"

    def test_config_path(self):
        """Test parsing config path with short option."""
        args = parse_args(["--config", "/path/to/config.toml"])
        assert args.config == Path("/path/to/config.toml")

        args = parse_args(["-c", "/path/to/config.toml"])
        assert args.config == Path("/path/to/config.toml")

    def test_short_options(self):
        """Test all short options work correctly."""
        args = parse_args(
            [
                "-c",
                "config.toml",
                "-H",
                "127.0.0.1",
                "-p",
                "9000",
                "-l",
                "DEBUG",
            ],
        )
        assert args.config == Path("config.toml")
        assert args.host == "127.0.0.1"
        assert args.port == 9000
        assert args.log_level == "DEBUG"


class TestLoadConfigOverrides:
    """Tests for CLI overrides in load_config."""

    def test_host_port_overrides(self):
        """Test that host and port CLI args override config."""
        args = parse_args(["--host", "127.0.0.1", "--port", "9000"])
        config = load_config(args)
        assert config.server.host == "127.0.0.1"
        assert config.server.port == 9000

    def test_log_level_override(self):
        """Test that log level CLI arg overrides config."""
        args = parse_args(["--log-level", "DEBUG"])
        config = load_config(args)
        assert config.logging.level == "DEBUG"


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_valid_config(self):
        data = {
            "server": {"host": "127.0.0.1", "port": 8080},
            "auth": {"enabled": True, "tokens": ["token1"]},
            "logging": {"level": "DEBUG", "file_enabled": True},
            "health": {"enabled": True},
        }
        # Should not raise
        validate_config_dict(data)

    def test_invalid_port_type(self):
        # "not_a_number" cannot be coerced to int
        data = {"server": {"port": "not_a_number"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config_dict(data, Path("config.toml"))
        error_msg = str(exc_info.value)
        assert "server.port" in error_msg
        assert "int" in error_msg
        assert "not_a_number" in error_msg

    def test_coercible_port_type(self):
        # "8080" can be coerced to int 8080
        data = {"server": {"port": "8080"}}
        validate_config_dict(data)  # Should not raise

    def test_coercible_bool_type(self):
        # "true" can be coerced to True
        data = {"auth": {"enabled": "true"}}
        validate_config_dict(data)  # Should not raise

    def test_invalid_tokens_type(self):
        data = {"auth": {"tokens": "single_token"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config_dict(data)
        error_msg = str(exc_info.value)
        assert "auth.tokens" in error_msg
        assert "list" in error_msg

    def test_error_shows_config_path(self):
        data = {"server": {"port": "invalid"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config_dict(data, Path("/path/to/config.toml"))
        error_msg = str(exc_info.value)
        assert "/path/to/config.toml" in error_msg

    def test_health_invalid_bool(self):
        # "anything" cannot be coerced to bool
        data = {"health": {"enabled": "anything"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config_dict(data)
        error_msg = str(exc_info.value)
        assert "health.enabled" in error_msg
        assert "bool" in error_msg
