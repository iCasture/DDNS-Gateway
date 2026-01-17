"""
CLI entry point for DDNS Gateway.

This module provides the command-line interface for starting the server.
It parses arguments, loads configuration, creates the app via the factory
function, and runs it with uvicorn.
"""

from __future__ import annotations

import logging
import sys

import uvicorn

from ddns_gateway.config import ConfigValidationError, load_config, parse_args
from ddns_gateway.logging_config import build_uvicorn_log_config, setup_logging
from ddns_gateway.server import create_app


def main() -> None:
    """
    Start the DDNS Gateway server.

    Parse command-line arguments, load configuration, create the app,
    and run the server with uvicorn.
    """
    args = parse_args()
    try:
        config = load_config(args)
    except ConfigValidationError as e:
        print(e, file=sys.stderr)  # noqa: T201
        sys.exit(1)

    setup_logging(config.logging)

    # Warn if binding to all interfaces
    if config.server.host == "0.0.0.0":  # noqa: S104
        logger = logging.getLogger(__name__)
        logger.warning(
            'Binding to "0.0.0.0" exposes the service to all network interfaces. '
            "This is a security risk if the service is not behind a reverse proxy. "
            'Consider using "127.0.0.1" for local-only access.',
        )

    # Create the app using the factory function
    app = create_app(config)

    # Run the app with uvicorn, passing the app object directly
    # This avoids reload/workers issues with import strings
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level=config.logging.level.lower(),
        access_log=True,
        log_config=build_uvicorn_log_config(config.logging),
    )


if __name__ == "__main__":
    main()
