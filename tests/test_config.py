"""Tests for configuration module."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import pytest

from ddns_gateway.config import (
    AuthConfig,
    ConfigValidationError,
    HealthConfig,
    LoggingConfig,
    MethodsConfig,
    ServerConfig,
    dict_to_config,
    load_config,
    load_config_from_file,
    merge_config,
    parse_args,
    parse_methods_str,
    validate_config_dict,
)


class TestServerConfig:
    """Tests for ServerConfig."""

    def test_default_values(self):
        config = ServerConfig()
        assert config.host == "0.0.0.0"
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


class TestMethodsConfig:
    """Tests for MethodsConfig."""

    def test_default_values(self):
        config = MethodsConfig()
        assert config.get_enabled is True
        assert config.post_enabled is True


class TestHealthConfig:
    """Tests for HealthConfig."""

    def test_default_values(self):
        config = HealthConfig()
        assert config.enabled is False


class TestLoggingConfig:
    """Tests for LoggingConfig."""

    def test_default_values(self):
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.file_enabled is False
        assert config.file_path == "/var/log/ddns-gateway.log"


class TestMergeConfig:
    """Tests for merge_config function."""

    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = merge_config(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"server": {"host": "0.0.0.0", "port": 38080}}
        override = {"server": {"port": 9000}}
        result = merge_config(base, override)
        assert result == {"server": {"host": "0.0.0.0", "port": 9000}}


class TestDictToConfig:
    """Tests for dict_to_config function."""

    def test_empty_dict(self):
        config = dict_to_config({})
        assert config.server.host == "0.0.0.0"
        assert config.server.port == 38080
        assert config.auth.enabled is False
        assert config.health.enabled is False

    def test_full_dict(self):
        data = {
            "server": {"host": "127.0.0.1", "port": 9000},
            "auth": {"enabled": False, "tokens": ["test"]},
            "methods": {"get_enabled": True, "post_enabled": False},
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
        assert config.methods.post_enabled is False
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


class TestParseMethodsStr:
    """Tests for parse_methods_str function."""

    def test_parse_valid_methods(self):
        config = parse_methods_str("get,post")
        assert config
        assert config.get_enabled
        assert config.post_enabled

        config = parse_methods_str("GET")
        assert config
        assert config.get_enabled
        assert not config.post_enabled

        config = parse_methods_str("post")
        assert config
        assert not config.get_enabled
        assert config.post_enabled

    def test_parse_invalid_methods(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_methods_str("invalid")

        with pytest.raises(argparse.ArgumentTypeError):
            parse_methods_str("get,invalid")

    def test_parse_empty(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_methods_str("")


class TestParseArgs:
    """Tests for parse_args function."""

    def test_default_args(self):
        args = parse_args([])
        assert args.config is None
        assert args.host is None
        assert args.port is None
        assert args.log_level is None
        assert args.auth_enabled is None
        assert args.auth_tokens is None
        assert args.methods is None
        assert args.log_file_enabled is None
        assert args.log_file_path is None

    def test_custom_args(self):
        args = parse_args(
            ["--host", "127.0.0.1", "--port", "9000", "--log-level", "DEBUG"],
        )
        assert args.host == "127.0.0.1"
        assert args.port == 9000
        assert args.log_level == "DEBUG"

    def test_config_path(self):
        args = parse_args(["--config", "/path/to/config.toml"])
        assert args.config == Path("/path/to/config.toml")

    def test_auth_enabled_disabled(self):
        args = parse_args(["--auth-enabled"])
        assert args.auth_enabled is True

        args = parse_args(["--auth-disabled"])
        assert args.auth_enabled is False

    def test_auth_tokens(self):
        # Test basic list
        args = parse_args(["--auth-tokens", "a", "b"])
        assert args.auth_tokens == ["a", "b"]

        # Test extend
        args = parse_args(["--auth-tokens", "a", "--auth-tokens", "b"])
        assert args.auth_tokens == ["a", "b"]

        # Test with subsequent flags
        try:
            # Need to use a full parser test to verify flag termination properly
            # argparse behavior is such that the next flag terminates nargs='+'
            args = parse_args(["--auth-tokens", "a", "b", "--log-level", "INFO"])
            assert args.auth_tokens == ["a", "b"]
            assert args.log_level == "INFO"
        except SystemExit:
            pytest.fail("Argument parsing failed on flag boundary")

    def test_methods(self):
        args = parse_args(["--methods", "get,post"])
        assert args.methods.get_enabled
        assert args.methods.post_enabled

        args = parse_args(["--methods", "post"])
        assert not args.methods.get_enabled
        assert args.methods.post_enabled

    def test_log_file_enabled_disabled(self):
        args = parse_args(["--log-file-enabled"])
        assert args.log_file_enabled is True

        args = parse_args(["--log-file-disabled"])
        assert args.log_file_enabled is False

    def test_log_file_path(self):
        args = parse_args(["--log-file-path", "/custom/log.path"])
        assert isinstance(args.log_file_path, Path)
        assert args.log_file_path == Path("/custom/log.path")


class TestLoadConfigOverrides:
    """Tests for CLI overrides in load_config."""

    def test_auth_override(self):
        # Create a parsed args object with overrides
        args = parse_args(["--auth-enabled", "--auth-tokens", "cli_token"])
        config = load_config(args)
        assert config.auth.enabled is True
        assert config.auth.tokens == ["cli_token"]

    def test_methods_override(self):
        args = parse_args(["--methods", "post"])
        config = load_config(args)
        assert config.methods.get_enabled is False
        assert config.methods.post_enabled is True

    def test_logging_override(self):
        args = parse_args(
            ["--log-file-enabled", "--log-file-path", "/tmp/cli.log"],
        )
        config = load_config(args)
        assert config.logging.file_enabled is True
        assert config.logging.file_path == str(Path("/tmp/cli.log").expanduser())


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_valid_config(self):
        data = {
            "server": {"host": "127.0.0.1", "port": 8080},
            "auth": {"enabled": True, "tokens": ["token1"]},
            "methods": {"get_enabled": True, "post_enabled": False},
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

    def test_invalid_bool_type(self):
        # "abc" cannot be coerced to bool
        data = {"methods": {"get_enabled": "abc"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config_dict(data, Path("config.toml"))
        error_msg = str(exc_info.value)
        assert "methods.get_enabled" in error_msg
        assert "bool" in error_msg

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
