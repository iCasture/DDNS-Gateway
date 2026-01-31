"""
Configuration management for DDNS Gateway.

This module handles loading and validating configuration from TOML files
and command-line arguments. Configuration priority (high to low):
1. Command-line arguments
2. Configuration file
3. Default values
"""

from __future__ import annotations

import argparse
import copy
import logging
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ValidationError

from ddns_gateway.logging_config import DATE_FORMAT, LOG_FORMAT, ShortNameFormatter

if TYPE_CHECKING:
    from typing import Any

# Configure basic logging for early startup messages.
# This ensures log messages during config loading (before "setup_logging()" is called)
# are visible with proper formatting. The main logging setup in "setup_logging()"
# will reconfigure the "ddns_gateway" logger with full settings later.
# Note: Logs from this logger will not be output to a file as the log file path has not been parsed yet.
logger_basic = logging.getLogger(__name__)
logger_basic.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = ShortNameFormatter(
    fmt=LOG_FORMAT,
    datefmt=DATE_FORMAT,
)
handler.setFormatter(formatter)
logger_basic.addHandler(handler)
logger_basic.propagate = False


class ConfigValidationError(Exception):
    """
    Exception raised when configuration validation fails.

    This exception is raised when the TOML configuration contains
    invalid types or values.

    Attributes
    ----------
    message : str
        Human-readable error message describing the validation failures.
    config_path : Path | None
        Path to the configuration file that failed validation.
    """

    def __init__(self, message: str, config_path: Path | None = None) -> None:
        """
        Initialize ConfigValidationError.

        Parameters
        ----------
        message : str
            Human-readable error message.
        config_path : Path | None, optional
            Path to the configuration file.
        """
        self.config_path = config_path
        super().__init__(message)


# Configuration models (Pydantic with type validation and coercion)


class ServerConfig(BaseModel):
    """
    Server configuration.

    Attributes
    ----------
    host : str
        Host address to bind to. Default is 127.0.0.1 for security.
    port : int
        Port number to listen on.
    """

    host: str = "127.0.0.1"
    port: int = 38080


class AuthConfig(BaseModel):
    """
    Authentication configuration.

    Attributes
    ----------
    enabled : bool
        Whether authentication is enabled.
    tokens : list[str]
        List of valid authentication tokens.
    """

    enabled: bool = False
    tokens: list[str] = []


class LoggingConfig(BaseModel):
    """
    Logging configuration.

    Attributes
    ----------
    level : str
        Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    file_enabled : bool
        Whether to log to file.
    file_path : str
        Path to the log file.
    """

    level: str = "INFO"
    file_enabled: bool = False
    file_path: str = "./logs/ddns-gateway.log"

    @property
    def file_path_as_path(self) -> Path:
        """
        Get the log file path as a Path object.

        Returns
        -------
        Path
            The resolved log file path.
        """
        return Path(self.file_path)


class HealthConfig(BaseModel):
    """
    Health endpoint configuration.

    Attributes
    ----------
    enabled : bool
        Whether the /health endpoint is enabled.
    """

    enabled: bool = False


class DedupePersistConfig(BaseModel):
    """
    Dedupe cache persistence configuration.

    Attributes
    ----------
    enabled : bool
        Whether to persist cache to SQLite.
    path : str
        SQLite file path.
    flush_interval_seconds : int
        How often to flush cache to SQLite.
    flush_on_startup : bool
        Whether to flush immediately after loading on startup.
    """

    enabled: bool = False
    path: str = "./data/dedupe.db"
    flush_interval_seconds: int = 600
    flush_on_startup: bool = True


class DedupeConfig(BaseModel):
    """
    Request deduplication configuration.

    Attributes
    ----------
    enabled : bool
        Whether deduplication is enabled.
    window_seconds : int
        Time window in seconds for deduplication.
    max_entries : int
        Maximum number of cache entries.
    singleflight_wait_timeout_sec : float
        Maximum time (seconds) for waiters to wait for leader's result.
        If exceeded, waiter returns error (does not start new request).
        Should be >= (request_timeout * max_attempts) + backoff_total + margin.
    singleflight_lease_sec : float
        In-flight lease duration (seconds). If leader doesn't complete within
        this time, waiters may "takeover" as new leader. Should be >= 2x wait_timeout.
    persist : DedupePersistConfig
        Persistence configuration.
    """

    enabled: bool = True
    window_seconds: int = 300
    max_entries: int = 1000
    singleflight_wait_timeout_sec: float = 30.0
    singleflight_lease_sec: float = 60.0
    persist: DedupePersistConfig = DedupePersistConfig()


class RetryConfig(BaseModel):
    """
    Automatic retry configuration for upstream API calls.

    Attributes
    ----------
    enabled : bool
        Whether automatic retry is enabled.
    max_attempts : int
        Maximum number of attempts (including first).
    request_timeout_sec : float
        Per-request timeout in seconds.
    base_delay_ms : int
        Base delay in milliseconds.
    max_delay_ms : int
        Maximum delay in milliseconds.
    jitter : bool
        Whether to add random jitter.
    on_http_status : list[int]
        HTTP status codes that trigger retry.
    """

    enabled: bool = True
    max_attempts: int = 3
    request_timeout_sec: float = 7.0
    base_delay_ms: int = 1000
    max_delay_ms: int = 10000
    jitter: bool = True
    on_http_status: list[int] = [429, 500, 502, 503, 504]


class ResponseConfig(BaseModel):
    """
    Response format configuration.

    Attributes
    ----------
    include_debug_info : bool
        Whether to include debug info (raw input, normalized) in response.
    """

    include_debug_info: bool = False


class Config(BaseModel):
    """
    Application configuration.

    Attributes
    ----------
    server : ServerConfig
        Server configuration.
    auth : AuthConfig
        Authentication configuration.
    logging : LoggingConfig
        Logging configuration.
    health : HealthConfig
        Health endpoint configuration.
    dedupe : DedupeConfig
        Request deduplication configuration.
    retry : RetryConfig
        Automatic retry configuration.
    response : ResponseConfig
        Response format configuration.
    """

    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    logging: LoggingConfig = LoggingConfig()
    health: HealthConfig = HealthConfig()
    dedupe: DedupeConfig = DedupeConfig()
    retry: RetryConfig = RetryConfig()
    response: ResponseConfig = ResponseConfig()


def _format_validation_errors(
    error: ValidationError,
    config_path: Path | None,
) -> str:
    """
    Format Pydantic validation errors into human-readable messages.

    Parameters
    ----------
    error : ValidationError
        Pydantic validation error.
    config_path : Path | None
        Path to the configuration file.

    Returns
    -------
    str
        Human-readable error message.
    """
    lines: list[str] = []

    if config_path:
        lines.append(f'Configuration error in "{config_path}":')
    else:
        lines.append("Configuration error:")

    for err in error.errors():
        # Build field path (e.g., "server.port")
        field_path = ".".join(str(loc) for loc in err["loc"])

        # Get error details
        error_type = err["type"]
        error_input = err["input"]
        input_type = type(error_input).__name__

        # Format the value for display
        value_repr = (
            f'"{error_input}"' if isinstance(error_input, str) else repr(error_input)
        )

        # Determine expected type from error type
        expected_type = _get_expected_type(error_type)
        lines.append(
            f"  [{field_path}]: Expected {expected_type}, got {input_type} (value: {value_repr}). {err['msg']}.",
        )

    return "\n".join(lines)


def _get_expected_type(error_type: str) -> str:
    """
    Get human-readable expected type from Pydantic error type.

    Parameters
    ----------
    error_type : str
        Pydantic error type string.

    Returns
    -------
    str
        Human-readable type name.
    """
    type_mapping = {
        "int_type": "int",
        "int_parsing": "int",
        "bool_type": "bool",
        "bool_parsing": "bool",
        "string_type": "str",
        "list_type": "list",
    }
    return type_mapping.get(error_type, error_type)


def validate_config_dict(
    data: dict[str, Any],
    config_path: Path | None = None,
) -> None:
    """
    Validate configuration dictionary using Pydantic.

    Parameters
    ----------
    data : dict[str, Any]
        Configuration dictionary to validate.
    config_path : Path | None, optional
        Path to the configuration file (for error messages).

    Raises
    ------
    ConfigValidationError
        If validation fails.
    """
    try:
        Config(**data)
    except ValidationError as e:
        msg = _format_validation_errors(e, config_path)
        raise ConfigValidationError(msg, config_path) from e


def load_config_from_file(config_path: Path) -> dict[str, Any]:
    """
    Load configuration from a TOML file.

    Parameters
    ----------
    config_path : Path
        Path to the configuration file.

    Returns
    -------
    dict[str, Any]
        Parsed configuration dictionary.

    Raises
    ------
    FileNotFoundError
        If the configuration file does not exist.
    tomllib.TOMLDecodeError
        If the configuration file is not valid TOML.
    """
    with config_path.open("rb") as f:
        return tomllib.load(f)


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively merge two configuration dictionaries.

    Parameters
    ----------
    base : dict[str, Any]
        Base configuration.
    override : dict[str, Any]
        Override configuration (takes precedence).

    Returns
    -------
    dict[str, Any]
        Merged configuration.
    """
    # Use deep copy to avoid modifying the original base configuration
    result = copy.deepcopy(base)

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_config(result[key], value)
        else:
            result[key] = value
    return result


def dict_to_config(data: dict[str, Any]) -> Config:
    """
    Convert a dictionary to a Config object.

    Parameters
    ----------
    data : dict[str, Any]
        Configuration dictionary.

    Returns
    -------
    Config
        Configuration object.
    """
    # Handle file_path expansion before Pydantic validation
    if "logging" in data and "file_path" in data["logging"]:
        data = copy.deepcopy(data)
        data["logging"]["file_path"] = str(
            Path(data["logging"]["file_path"]).expanduser(),
        )

    return Config.model_validate(data)


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command-line arguments.

    Only essential arguments are supported via CLI. Other settings should be
    configured via the configuration file.

    Parameters
    ----------
    args : list[str] | None, optional
        Command-line arguments. If None, uses sys.argv.

    Returns
    -------
    argparse.Namespace
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="ddns-gateway",
        description="DDNS Gateway - A DDNS update service for RouterOS",
    )

    # Config file
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        help="Path to configuration file (default: ./config.toml if present)",
    )

    # Server settings
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default=None,
        help="Server bind host (overrides server.host)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=None,
        help="Server bind port (overrides server.port)",
    )

    # Logging
    parser.add_argument(
        "-l",
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help=(
            "Logging level for server logs (DEBUG=most verbose; "
            "unrelated to response debug info)"
        ),
    )

    # Response settings
    response_group = parser.add_mutually_exclusive_group()
    response_group.add_argument(
        "-d",
        "--response-debug-info",
        dest="response_debug_info",
        action="store_true",
        default=None,
        help=("Include response debug details (overrides response.include_debug_info)"),
    )
    response_group.add_argument(
        "-D",
        "--no-response-debug-info",
        dest="response_debug_info",
        action="store_false",
        help=("Disable response debug details (overrides response.include_debug_info)"),
    )

    return parser.parse_args(args)


def load_config(args: argparse.Namespace | None = None) -> Config:
    """
    Load configuration from file and command-line arguments.

    Priority (high to low):
    1. Command-line arguments
    2. Configuration file
    3. Default values

    Parameters
    ----------
    args : argparse.Namespace | None, optional
        Parsed command-line arguments.

    Returns
    -------
    Config
        Loaded configuration.
    """
    if args is None:
        args = parse_args()

    # Start with empty config dict
    config_dict: dict[str, Any] = {}

    # Load from config file if specified or if default exists
    config_path = args.config
    if config_path is not None:
        config_path = config_path.expanduser()
    if config_path is None:
        default_config = Path("./config.toml")
        if default_config.exists():
            config_path = default_config

    if config_path is not None:
        if config_path.exists():
            logger_basic.info('Loading configuration from "%s".', config_path)
            try:
                config_dict = load_config_from_file(config_path)
            except tomllib.TOMLDecodeError as e:
                logger_basic.critical('Failed to parse configuration file: "%s".', e)
                sys.exit(1)
        else:
            logger_basic.critical("Configuration file not found: %s", config_path)
            sys.exit(1)

    # Apply command-line overrides
    cli_overrides: dict[str, Any] = {}

    # Server overrides
    if args.host is not None:
        cli_overrides.setdefault("server", {})["host"] = args.host
    if args.port is not None:
        cli_overrides.setdefault("server", {})["port"] = args.port

    # Logging overrides
    if args.log_level is not None:
        cli_overrides.setdefault("logging", {})["level"] = args.log_level

    # Response overrides
    if args.response_debug_info is not None:
        cli_overrides.setdefault("response", {})["include_debug_info"] = (
            args.response_debug_info
        )

    if cli_overrides:
        config_dict = merge_config(config_dict, cli_overrides)

    # Validate merged configuration
    validate_config_dict(config_dict, config_path)

    return dict_to_config(config_dict)
