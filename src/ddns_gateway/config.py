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

from pydantic import BaseModel, ValidationError, model_validator
from pydantic_core import PydanticCustomError

from ddns_gateway.logging_config import DATE_FORMAT, LOG_FORMAT

if TYPE_CHECKING:
    from typing import Any, Self

# Configure basic logging for early startup messages.
# This ensures log messages during config loading (before "setup_logging()" is called)
# are visible with proper formatting. The main logging setup in "setup_logging()"
# will reconfigure the "ddns_gateway" logger with full settings later.
# Note: Logs from this logger will not be output to a file as the log file path has not been parsed yet.
logger_basic = logging.getLogger(__name__)
logger_basic.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter(
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
        Host address to bind to.
    port : int
        Port number to listen on.
    """

    host: str = "0.0.0.0"  # noqa: S104
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


class MethodsConfig(BaseModel):
    """
    HTTP methods configuration.

    Attributes
    ----------
    get_enabled : bool
        Whether GET method is enabled.
    post_enabled : bool
        Whether POST method is enabled.
    """

    get_enabled: bool = True
    post_enabled: bool = True

    @model_validator(mode="after")
    def check_at_least_one_method_enabled(self) -> Self:
        """
        Validate that at least one method is enabled.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        PydanticCustomError
            If both GET and POST methods are disabled.
        """
        if not self.get_enabled and not self.post_enabled:
            err_type = "methods_config_error"
            raise PydanticCustomError(
                err_type,
                "At least one HTTP method must be enabled (GET or POST)",
            )
        return self


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
    file_path: str = "/var/log/ddns-gateway.log"

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


class Config(BaseModel):
    """
    Application configuration.

    Attributes
    ----------
    server : ServerConfig
        Server configuration.
    auth : AuthConfig
        Authentication configuration.
    methods : MethodsConfig
        HTTP methods configuration.
    logging : LoggingConfig
        Logging configuration.
    health : HealthConfig
        Health endpoint configuration.
    """

    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    methods: MethodsConfig = MethodsConfig()
    logging: LoggingConfig = LoggingConfig()
    health: HealthConfig = HealthConfig()


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

        if error_type == "methods_config_error":
            # lines.append(f"  [{field_path}]: {err['msg']} ({value_repr}).")
            lines.append(
                f"  [{field_path}]: {err['msg']}: {', '.join(f'"{k}": {v}' for k, v in error_input.items())}.",  # pyright: ignore[reportAttributeAccessIssue]
            )
        else:
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


def parse_methods_str(value: str) -> MethodsConfig:
    """
    Parse methods string from CLI.

    This function is intended to be used as a `type` converter in `argparse`.

    Parameters
    ----------
    value : str
        Comma-separated list of methods (e.g., "get,post").

    Returns
    -------
    MethodsConfig
        Methods configuration.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value contains invalid methods.
    """
    if not value:
        msg = "No methods specified."
        raise argparse.ArgumentTypeError(msg)

    methods = [m.strip().lower() for m in value.split(",") if m.strip()]

    if not methods:
        msg = "No methods specified."
        raise argparse.ArgumentTypeError(msg)

    get_enabled = False
    post_enabled = False

    for method in methods:
        if method == "get":
            get_enabled = True
        elif method == "post":
            post_enabled = True
        else:
            msg = f'Invalid method: "{method}".'
            raise argparse.ArgumentTypeError(msg)

    return MethodsConfig(get_enabled=get_enabled, post_enabled=post_enabled)


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

    # Config arguments
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to configuration file (default: config.toml)",
    )

    # Server arguments
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host address to bind to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port number to listen on",
    )

    # Auth arguments
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--auth-enabled",
        action="store_true",
        dest="auth_enabled",
        default=None,
        help="Enable authentication",
    )
    auth_group.add_argument(
        "--auth-disabled",
        action="store_false",
        dest="auth_enabled",
        default=None,
        help="Disable authentication",
    )
    parser.add_argument(
        "--auth-tokens",
        nargs="+",
        action="extend",
        dest="auth_tokens",
        default=None,
        help="Authentication tokens",
    )

    # Methods arguments
    parser.add_argument(
        "--methods",
        type=parse_methods_str,
        dest="methods",
        default=None,
        help="Enabled HTTP methods (comma-separated, e.g., 'get,post')",
    )

    # Logging arguments
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Log level",
    )
    log_file_group = parser.add_mutually_exclusive_group()
    log_file_group.add_argument(
        "--log-file-enabled",
        action="store_true",
        dest="log_file_enabled",
        default=None,
        help="Enable logging to file",
    )
    log_file_group.add_argument(
        "--log-file-disabled",
        action="store_false",
        dest="log_file_enabled",
        default=None,
        help="Disable logging to file",
    )
    parser.add_argument(
        "--log-file-path",
        type=Path,
        dest="log_file_path",
        default=None,
        help="Path to the log file",
    )

    # Health endpoint arguments
    health_group = parser.add_mutually_exclusive_group()
    health_group.add_argument(
        "--health-enabled",
        action="store_true",
        dest="health_enabled",
        default=None,
        help='Enable "/health" endpoint',
    )
    health_group.add_argument(
        "--health-disabled",
        action="store_false",
        dest="health_enabled",
        default=None,
        help='Disable "/health" endpoint',
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
        default_config = Path("config.toml")
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

    # Auth overrides
    if args.auth_enabled is not None:
        cli_overrides.setdefault("auth", {})["enabled"] = args.auth_enabled
    if args.auth_tokens is not None:
        cli_overrides.setdefault("auth", {})["tokens"] = args.auth_tokens

    # Methods overrides
    if args.methods is not None:
        methods_config: MethodsConfig = args.methods
        cli_overrides.setdefault("methods", {})["get_enabled"] = (
            methods_config.get_enabled
        )
        cli_overrides.setdefault("methods", {})["post_enabled"] = (
            methods_config.post_enabled
        )

    # Logging overrides
    if args.log_level is not None:
        cli_overrides.setdefault("logging", {})["level"] = args.log_level
    if args.log_file_enabled is not None:
        cli_overrides.setdefault("logging", {})["file_enabled"] = args.log_file_enabled
    if args.log_file_path is not None:
        cli_overrides.setdefault("logging", {})["file_path"] = str(args.log_file_path)

    # Health overrides
    if args.health_enabled is not None:
        cli_overrides.setdefault("health", {})["enabled"] = args.health_enabled

    if cli_overrides:
        config_dict = merge_config(config_dict, cli_overrides)

    # Validate merged configuration
    validate_config_dict(config_dict, config_path)

    return dict_to_config(config_dict)
