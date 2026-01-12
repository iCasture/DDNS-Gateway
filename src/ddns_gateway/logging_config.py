"""
Logging configuration for DDNS Gateway.

This module provides logging setup with support for console and file output.
Sensitive information is automatically masked in log messages.
"""

from __future__ import annotations

import copy
import logging
import logging.handlers
import re
import sys
from typing import TYPE_CHECKING

from uvicorn.config import LOGGING_CONFIG

if TYPE_CHECKING:
    from typing import Final

    from ddns_gateway.config import LoggingConfig


# Pattern to match sensitive tokens/keys in log messages
# Each tuple is (pattern, replacement)
# For partial masking, capture the prefix to keep and mask the rest
SENSITIVE_PATTERNS: Final[list[tuple[re.Pattern[str], str]]] = [
    # Authorization header (Bearer token for server auth)
    # Keep first 6 characters, mask the rest
    (
        re.compile(
            r"((?:Authorization:\s*)?Bearer\s+)(.{0,6})([^\s\"']*)", re.IGNORECASE,
        ),
        r"\1\2******",
    ),
    # X-Upstream-Authorization header (provider credentials)
    # Supports: id="...", id='...', id=... (unquoted)
    # Keep first 6 characters of id, mask the rest
    (
        re.compile(r'(id=")(.{0,6})([^"]*)"', re.IGNORECASE),
        r'\1\2******"',
    ),
    (
        re.compile(r"(id=')(.{0,6})([^']*)'", re.IGNORECASE),
        r"\1\2******'",
    ),
    (
        re.compile(r"(id=)(?![\"'])([^\s,\"&']{0,6})([^\s,\"&']*)", re.IGNORECASE),
        r"\1\2******",
    ),
    # Keep first 6 characters of secret, mask the rest
    (
        re.compile(r'(secret=")(.{0,6})([^"]*)"', re.IGNORECASE),
        r'\1\2******"',
    ),
    (
        re.compile(r"(secret=')(.{0,6})([^']*)'", re.IGNORECASE),
        r"\1\2******'",
    ),
    (
        re.compile(r"(secret=)(?![\"'])([^\s,\"&']{0,6})([^\s,\"&']*)", re.IGNORECASE),
        r"\1\2******",
    ),
    # # [for test only] tzgtkrcu52: keep first 6 characters
    # (
    #     re.compile(r"(tzgtkrcu52=)(.{0,6})([^\s&]*)", re.IGNORECASE),
    #     r"\1\2******",
    # ),
    # # [for test only] f59hvnc38u: mask completely
    # (
    #     re.compile(r"(f59hvnc38u=)([^\s&]+)", re.IGNORECASE),
    #     r"\1******",
    # ),
]


# Constants
LOG_FORMAT: Final[str] = "%(asctime)s %(levelname)-5s [%(name)s] %(message)s"
DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"


class SensitiveFilter(logging.Filter):
    """
    A logging filter that masks sensitive information.

    This filter replaces sensitive tokens and keys with asterisks
    to prevent credential leakage in log files.
    """

    # Fields in record.__dict__ that may contain sensitive data
    # These are set by formatters like uvicorn's AccessFormatter
    _SENSITIVE_DICT_KEYS: tuple[str, ...] = (
        "request_line",  # Uvicorn: "{method} {full_path} HTTP/{version}"
        "full_path",  # Custom formatters may use this
        "path",  # Request path
        "url",  # Full URL
        "headers",  # Request headers (if logged)
        "scope",  # ASGI scope (may contain headers)
    )

    @staticmethod
    def _mask_sensitive(value: str) -> str:
        """
        Apply all sensitive patterns to mask a string.

        Parameters
        ----------
        value : str
            The string to process.

        Returns
        -------
        str
            The string with sensitive data masked.
        """
        result = value
        for pattern, replacement in SENSITIVE_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter and modify log record to mask sensitive data.

        This handles:
        - record.msg (for standard log messages)
        - record.args (for formatted messages like uvicorn access logs)
        - record.__dict__ (for fields set by custom formatters)

        Parameters
        ----------
        record : logging.LogRecord
            The log record to process.

        Returns
        -------
        bool
            Always returns True (record is always logged).
        """
        # Mask record.msg
        if record.msg:
            record.msg = self._mask_sensitive(str(record.msg))

        # Mask record.args (used by uvicorn access logs and formatted messages)
        if record.args:
            if isinstance(record.args, dict):
                # Dict-style formatting: %(key)s
                record.args = {
                    k: self._mask_sensitive(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                # Tuple-style formatting: %s, %d, etc.
                record.args = tuple(
                    self._mask_sensitive(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )

        # Mask sensitive fields in record.__dict__ (defensive, for custom formatters)
        for key in self._SENSITIVE_DICT_KEYS:
            if key in record.__dict__:
                value = record.__dict__[key]
                if isinstance(value, str):
                    record.__dict__[key] = self._mask_sensitive(value)

        return True


def _configure_handler(handler: logging.Handler) -> None:
    """
    Configure a logging handler with formatter and sensitive filter.

    Parameters
    ----------
    handler : logging.Handler
        The handler to configure.
    """
    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
    sensitive_filter = SensitiveFilter()

    handler.setFormatter(formatter)
    handler.addFilter(sensitive_filter)


def setup_logging(config: LoggingConfig) -> None:
    """
    Set up logging based on configuration.

    Parameters
    ----------
    config : LoggingConfig
        Logging configuration.
    """
    # Get the root logger for the package
    logger = logging.getLogger("ddns_gateway")
    logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))

    # Clear any existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    _configure_handler(console_handler)
    logger.addHandler(console_handler)

    # File handler (if enabled)
    if config.file_enabled:
        log_path = config.file_path_as_path
        try:
            # Ensure log directory exists
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.handlers.WatchedFileHandler(
                str(log_path),
                encoding="utf-8",
                delay=False,
            )
            _configure_handler(file_handler)
            logger.addHandler(file_handler)
            logger.info('File logging enabled: "%s".', log_path)
        except OSError as e:
            # Re-raise as a fatal error after logging to console
            logger.critical("Failed to enable file logging: %s", e)
            sys.exit(1)

    # Prevent propagation to root logger
    logger.propagate = False


def build_uvicorn_log_config(config: LoggingConfig) -> dict:
    """
    Build uvicorn log configuration dictionary with file and console handlers.

    This function creates a log configuration for uvicorn that:
    - Preserves uvicorn's default console output (with colors)
    - Adds file logging when enabled
    - Applies sensitive information filtering to all handlers

    Parameters
    ----------
    config : LoggingConfig
        Logging configuration from the application.

    Returns
    -------
    dict
        A uvicorn-compatible log configuration dictionary.

    Raises
    ------
    SystemExit
        If file logging is enabled but the log file cannot be created.
    """
    # Start with a deep copy of uvicorn's default config to avoid modifications
    log_config = copy.deepcopy(LOGGING_CONFIG)

    # Define sensitive information filter
    filter_config = {
        "()": f"{__name__}.SensitiveFilter",
    }
    log_config.setdefault("filters", {})["sensitive"] = filter_config

    # Apply sensitive filter to uvicorn's default console handlers
    log_config["handlers"]["default"].setdefault("filters", []).append("sensitive")
    log_config["handlers"]["access"].setdefault("filters", []).append("sensitive")

    # Add file logging if enabled
    if config.file_enabled:
        log_path = config.file_path_as_path

        # Validate file path and create directory if needed
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # Test if we can write to the file
            log_path.touch(exist_ok=True)
        except OSError as e:
            logger = logging.getLogger("ddns_gateway")
            logger.critical("Failed to create log file: %s", e)
            sys.exit(1)

        # Define file formatter with consistent format and date format
        formatter_config = {
            "format": LOG_FORMAT,
            "datefmt": DATE_FORMAT,
        }

        # Define file handler configuration
        handler_config = {
            "class": "logging.handlers.WatchedFileHandler",
            "filename": str(log_path),
            "encoding": "utf-8",
            "delay": False,
            "formatter": "file",
            "filters": ["sensitive"],
        }

        # Add custom formatter and handler to the configuration
        log_config.setdefault("formatters", {})["file"] = formatter_config
        log_config.setdefault("handlers", {})["file"] = handler_config

        # Add file handler to uvicorn loggers
        # Note: Only add to "uvicorn" and "uvicorn.access" explicitly
        # "uvicorn.error" will propagate to "uvicorn" automatically
        log_config["loggers"]["uvicorn"]["handlers"].append("file")
        log_config["loggers"]["uvicorn.access"]["handlers"].append("file")

    return log_config
