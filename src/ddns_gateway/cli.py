"""
CLI entry point for DDNS Gateway.

This module provides the command-line interface for starting the server.
"""

from __future__ import annotations

import sys

import uvicorn

from ddns_gateway.config import ConfigValidationError, load_config, parse_args
from ddns_gateway.logging_config import build_uvicorn_log_config, setup_logging
from ddns_gateway.server import set_preloaded_config


def main() -> None:
    """
    Start the DDNS Gateway server.

    Parse command-line arguments, load configuration, and run the server.
    """
    args = parse_args()
    try:
        config = load_config(args)
    except ConfigValidationError as e:
        print(e, file=sys.stderr)  # noqa: T201
        sys.exit(1)

    setup_logging(config.logging)

    # Inject the loaded configuration into the server module to prevent
    # re-parsing arguments when the app starts.
    set_preloaded_config(config)

    uvicorn.run(
        "ddns_gateway.server:app",
        host=config.server.host,
        port=config.server.port,
        log_level=config.logging.level.lower(),
        access_log=True,
        log_config=build_uvicorn_log_config(config.logging),
    )


if __name__ == "__main__":
    main()
