"""
FastAPI server for DDNS Gateway.

This module provides the main API server with endpoints for DNS record operations.
Supports PUT (upsert) and DELETE methods with authentication.

Configuration is managed via the ``create_app(config)`` factory function.
The config object is stored in ``app.state.config`` and accessible throughout
the application lifecycle.
"""

from __future__ import annotations

import json
import logging
import math
import re
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette import status as st_status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ddns_gateway.config import Config
from ddns_gateway.dedupe import DedupeCache
from ddns_gateway.models import (
    ERROR_STATUS_MAP,
    DDNSResponse,
    DebugInfo,
    DNSProvider,
    ErrorCode,
    ErrorModel,
    RecordInfo,
    ResponseMeta,
    UpsertRequest,
    WarningCode,
    WarningModel,
)
from ddns_gateway.providers.aliyun import AliyunProvider
from ddns_gateway.providers.cloudflare import CloudFlareProvider
from ddns_gateway.providers.tencent import TencentProvider
from ddns_gateway.service import delete_record_service, upsert_record_service

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from typing import Final

    from ddns_gateway.providers.base import BaseDNSProvider


logger = logging.getLogger(__name__)

# Provider instances (stateless singletons, can be shared across requests)
_providers: dict[DNSProvider, BaseDNSProvider] = {
    DNSProvider.CLOUDFLARE: CloudFlareProvider(),
    DNSProvider.ALIYUN: AliyunProvider(),
    DNSProvider.TENCENT: TencentProvider(),
}


def _get_http_status_code(response: DDNSResponse) -> int:
    """
    Determine HTTP status code based on response.

    Parameters
    ----------
    response : DDNSResponse
        The response object.

    Returns
    -------
    int
        HTTP status code: 200 for success, appropriate error code otherwise.
    """
    if response.status == "success":
        return 200

    # Check first error code for status mapping
    if response.errors:
        first_error = response.errors[0]
        error_code = first_error.code
        if error_code in ERROR_STATUS_MAP:
            return ERROR_STATUS_MAP[error_code]

    # Default to 400 Bad Request for unknown errors
    return 400


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware for authentication.

    Intercepts requests to `/v1/ddns/` endpoints to check:
    1. Authentication via Authorization header -> 401 if missing, 403 if invalid

    Configuration is accessed from ``request.app.state.config``.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process the request through authentication."""
        # Only apply to /v1/ddns/ paths
        if not request.url.path.startswith("/v1/ddns/"):
            return await call_next(request)

        # Access config from app.state
        config: Config = request.app.state.config

        # Skip auth check if disabled
        if not config.auth.enabled:
            return await call_next(request)

        # Extract Bearer token from Authorization header
        auth_header = request.headers.get("authorization", "")
        server_token: str | None = None
        if auth_header.lower().startswith("bearer "):
            server_token = auth_header[7:].strip()

        # Validate token
        if not server_token:
            client_ip = request.client.host if request.client else "unknown"
            has_auth_header = bool(auth_header)
            logger.debug(
                '[auth: server] Missing server token. Path: "%s", Method: "%s", Client IP: "%s", Has Auth Header: "%s".',
                request.url.path,
                request.method,
                client_ip,
                has_auth_header,
            )
            return JSONResponse(
                status_code=ERROR_STATUS_MAP.get(
                    ErrorCode.MISSING_AUTH_TOKEN,
                    st_status.HTTP_401_UNAUTHORIZED,
                ),
                content=DDNSResponse.error(
                    errors=ErrorModel(
                        code=ErrorCode.MISSING_AUTH_TOKEN,
                        message="Missing authentication token",
                    ),
                    provider="unknown",
                    zone="",
                    record_type="",
                    record_name="",
                ).model_dump(exclude_none=True),
            )
        if server_token not in config.auth.tokens:
            client_ip = request.client.host if request.client else "unknown"
            token_preview = (
                f"{server_token[:6]}..." if len(server_token) > 6 else "******"  # noqa: PLR2004
            )
            logger.debug(
                '[auth: server] Invalid server token. Path: "%s", Method: "%s", Client IP: "%s", Token Preview: "%s".',
                request.url.path,
                request.method,
                client_ip,
                token_preview,
            )
            return JSONResponse(
                status_code=ERROR_STATUS_MAP.get(
                    ErrorCode.INVALID_AUTH_TOKEN,
                    st_status.HTTP_403_FORBIDDEN,
                ),
                content=DDNSResponse.error(
                    errors=ErrorModel(
                        code=ErrorCode.INVALID_AUTH_TOKEN,
                        message="Invalid authentication token",
                    ),
                    provider="unknown",
                    zone="",
                    record_type="",
                    record_name="",
                ).model_dump(exclude_none=True),
            )

        return await call_next(request)


# =============================================================================
# Credential Parsing
# =============================================================================


# Regex pattern to parse X-Upstream-Authorization header
# Format examples:
#   - 'ApiKey id="<id>", secret="<secret>"'
#   - "ApiKey id='<id>', secret='<secret>'"
#   - 'ApiKey id=<id>, secret=<secret>'
#   - 'ApiKey secret="<secret>"'
#   - 'ApiKey secret=<secret>'
# Notes:
#   - Quotes are optional, but if used, must be paired (single or double).
#   - The `id` field is optional, but `secret` is always required.
#   - Formats with only `id` (without `secret`) are NOT supported.
#   - Field names (`id`, `secret`) are case-insensitive.
#   - Leading/trailing whitespace around values is stripped.
_UPSTREAM_AUTH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""
    ^\s*
        (?:
            # Pattern 1: id first, then secret
            id\s*=\s*
            (?:
                (?P<q1>["'])(?P<id1>(?:(?!(?P=q1)).)*?)(?P=q1)   # quoted
                |
                (?P<id1_nq>[^,\s]+)                             # unquoted
            )
            \s*,\s*
            secret\s*=\s*
            (?:
                (?P<q2>["'])(?P<secret1>(?:(?!(?P=q2)).)*?)(?P=q2)  # quoted
                |
                (?P<secret1_nq>[^,\s]+)                            # unquoted
            )
            |
            # Pattern 2: secret first, id optional
            secret\s*=\s*
            (?:
                (?P<q3>["'])(?P<secret2>(?:(?!(?P=q3)).)*?)(?P=q3)  # quoted
                |
                (?P<secret2_nq>[^,\s]+)                            # unquoted
            )
            (?:
                \s*,\s*
                id\s*=\s*
                (?:
                    (?P<q4>["'])(?P<id2>(?:(?!(?P=q4)).)*?)(?P=q4)  # quoted
                    |
                    (?P<id2_nq>[^,\s]+)                            # unquoted
                )
            )?
        )
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_upstream_auth(header_value: str) -> tuple[str | None, str | None]:
    """
    Parse the `X-Upstream-Authorization` header.

    Parameters
    ----------
    header_value : str
        The header value in format: `ApiKey id="<id>", secret="<secret>"`
        or `ApiKey secret="<secret>"` (`id` is optional).

    Returns
    -------
    tuple[str | None, str | None]
        A tuple of `(id, secret)` (stripped). Empty strings are treated as `None`.
        If parsing fails, returns `(None, None)`.
    """
    # Check "ApiKey " prefix
    if not header_value.lower().startswith("apikey "):
        return (None, None)

    # Remove "ApiKey" prefix
    header_keypair = header_value[6:].strip()

    match = _UPSTREAM_AUTH_PATTERN.match(header_keypair)

    if not match:
        return (None, None)

    def _get_group(match: re.Match[str], *names: str) -> str | None:
        """
        Get the first non-empty group value from a regex match.

        Parameters
        ----------
        match : re.Match[str]
            The regex match object.
        *names : str
            Group names to try in order.

        Returns
        -------
        str | None
            The stripped group value, or None if all groups are empty or unmatched.
        """
        for name in names:
            if value := match.group(name):
                return value.strip() or None
        return None

    header_id = _get_group(match, "id1", "id1_nq", "id2", "id2_nq")
    header_sec = _get_group(match, "secret1", "secret1_nq", "secret2", "secret2_nq")

    return (header_id, header_sec)


def extract_credentials_from_header(
    provider: DNSProvider,
    request: Request,
) -> dict[str, str]:
    """
    Extract provider credentials from X-Upstream-Authorization header.

    Parameters
    ----------
    provider : DNSProvider
        The DNS provider enum.
    request : Request
        The FastAPI request object.

    Returns
    -------
    dict[str, str]
        Credentials dictionary with provider-specific keys.
    """
    header_value = request.headers.get("x-upstream-authorization", "")
    client_ip = request.client.host if request.client else "unknown"
    if not header_value:
        logger.debug(
            '[auth: upstream] Missing X-Upstream-Authorization header. Path: "%s", Method: "%s", '
            'Client IP: "%s", Provider: "%s".',
            request.url.path,
            request.method,
            client_ip,
            provider.value,
        )
        return {}

    auth_id, auth_secret = parse_upstream_auth(header_value)
    if auth_id is None and auth_secret is None:
        logger.debug(
            '[auth: upstream] Invalid X-Upstream-Authorization format. Path: "%s", Method: "%s", '
            'Client IP: "%s", Provider: "%s", Has ApiKey Prefix: "%s", Header Length: "%s".',
            request.url.path,
            request.method,
            client_ip,
            provider.value,
            header_value.lower().startswith("apikey "),
            len(header_value),
        )
        return {}

    creds: dict[str, str] = {}
    has_id = bool(auth_id)
    has_secret = bool(auth_secret)

    if provider == DNSProvider.CLOUDFLARE:
        # Cloudflare only needs secret (token), id is ignored if provided
        if auth_secret:
            creds["secret"] = auth_secret
        else:
            logger.debug(
                '[auth: upstream] Missing credentials for provider. Path: "%s", Method: "%s", '
                'Client IP: "%s", Provider: "%s", Has Id: "%s", Has Secret: "%s".',
                request.url.path,
                request.method,
                client_ip,
                provider.value,
                has_id,
                has_secret,
            )
    elif provider in (DNSProvider.ALIYUN, DNSProvider.TENCENT):
        # Aliyun and Tencent use both id and secret
        if auth_id:
            creds["id"] = auth_id
        if auth_secret:
            creds["secret"] = auth_secret
        if not (has_id and has_secret):
            logger.debug(
                '[auth: upstream] Missing credentials for provider. Path: "%s", Method: "%s", '
                'Client IP: "%s", Provider: "%s", Has Id: "%s", Has Secret: "%s".',
                request.url.path,
                request.method,
                client_ip,
                provider.value,
                has_id,
                has_secret,
            )

    return creds


# =============================================================================
# App Factory
# =============================================================================


def create_app(config: Config) -> FastAPI:
    """
    Create and configure the FastAPI application.

    This factory function creates a new FastAPI instance with the provided
    configuration. The config is stored in ``app.state.config`` and accessible
    throughout the application.

    Parameters
    ----------
    config : Config
        The application configuration object.

    Returns
    -------
    FastAPI
        The configured FastAPI application instance.

    Examples
    --------
    >>> from ddns_gateway.config import load_config
    >>> config = load_config()
    >>> app = create_app(config)
    >>> # Run with uvicorn
    >>> import uvicorn
    >>> uvicorn.run(app, host=config.server.host, port=config.server.port)
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        """
        Application lifespan manager.

        Initializes app.state with config and dedupe cache.
        The config object is captured from the enclosing create_app scope.
        """
        # Store the config in app.state for access throughout the app
        app.state.config = config

        # Initialize DedupeCache if enabled
        if config.dedupe.enabled:
            app.state.dedupe_cache = DedupeCache(
                max_entries=config.dedupe.max_entries,
                window_seconds=config.dedupe.window_seconds,
            )
            logger.info(
                '[lifespan] DedupeCache initialized (Max Entries: "%d", Window: "%ds").',
                config.dedupe.max_entries,
                config.dedupe.window_seconds,
            )
        else:
            app.state.dedupe_cache = None
            logger.info("[lifespan] DedupeCache disabled.")

        # Dynamically register "/health" endpoint (GET method) if enabled
        if config.health.enabled:
            app.add_api_route("/health", health, methods=["GET"])

        logger.info(
            'DDNS Gateway starting on "%s:%d".',
            config.server.host,
            config.server.port,
        )

        yield

        logger.info("DDNS Gateway shutting down.")

    # Create FastAPI app
    app = FastAPI(
        title="DDNS Gateway",
        description="DDNS update service for RouterOS - bridges ROS scripts with DNS providers",
        version="0.2.0",
        lifespan=lifespan,
    )

    # Add middleware for authentication
    app.add_middleware(AuthMiddleware)

    # Register exception handlers (order matters: more specific first)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)  # Fallback

    # Register API routes
    app.add_api_route(
        "/v1/ddns/{provider}/{zone}/{record_type}/{record}",
        upsert_ddns_record,
        methods=["PUT"],
    )
    app.add_api_route(
        "/v1/ddns/{provider}/{zone}/{record_type}/{record}",
        delete_ddns_record,
        methods=["DELETE"],
    )

    return app


# =============================================================================
# Exception Handlers
# =============================================================================


def _should_include_debug_info(request: Request) -> bool:
    """
    Safely get ``include_debug_info`` from ``app.state.config``.

    Returns ``False`` if config is not available (e.g., during startup errors).
    """
    try:
        config: Config = request.app.state.config
    except AttributeError:
        return False
    return config.response.include_debug_info


async def http_exception_handler(request: Request, exc: Exception) -> Response:
    """
    Handle HTTP exceptions with consistent JSON responses.

    Convert FastAPI's default {"detail": "..."} format to the unified
    API response format. Internal details are hidden from the response
    and only included in debug info when enabled.
    """
    # Type narrowing for the actual exception type
    http_exc = exc if isinstance(exc, HTTPException) else HTTPException(500, str(exc))

    # Hide internal details from user-facing message
    is_server_error = (
        st_status.HTTP_500_INTERNAL_SERVER_ERROR
        <= http_exc.status_code
        < st_status.HTTP_500_INTERNAL_SERVER_ERROR + 100
    )
    user_message = "Server error" if is_server_error else "Request error"

    include_debug = _should_include_debug_info(request)
    client_ip = request.client.host if request.client else "unknown"

    log_level = logging.ERROR if is_server_error else logging.DEBUG
    logger.log(
        log_level,
        '[request] HTTPException. Path: "%s", Method: "%s", Client IP: "%s", '
        'Status: "%s", Detail: "%s".',
        request.url.path,
        request.method,
        client_ip,
        http_exc.status_code,
        str(http_exc.detail),
    )

    return JSONResponse(
        status_code=http_exc.status_code,
        content=DDNSResponse.error(
            errors=ErrorModel(
                code=ErrorCode.INTERNAL_ERROR,
                message=user_message,
            ),
            provider="unknown",
            zone="",
            record_type="",
            record_name="",
            include_debug_info=include_debug,
            raw_input={},
            extra={
                "original_status_code": http_exc.status_code,
                "original_detail": str(http_exc.detail),
            },
        ).model_dump(exclude_none=True),
    )


async def validation_exception_handler(request: Request, exc: Exception) -> Response:
    """
    Handle validation errors with consistent JSON responses.

    Convert FastAPI's validation error format to the unified API response format,
    listing all missing or invalid fields in the message. Internal details are
    hidden from the response and only included in debug info when enabled.
    """
    include_debug = _should_include_debug_info(request)

    # Type narrowing for the actual exception type
    if not isinstance(exc, RequestValidationError):
        client_ip = request.client.host if request.client else "unknown"
        logger.error(
            '[request] Unexpected validation exception type. Path: "%s", Method: "%s", '
            'Client IP: "%s", Exception: "%s", Message: "%s".',
            request.url.path,
            request.method,
            client_ip,
            type(exc).__name__,
            str(exc),
        )
        return JSONResponse(
            status_code=ERROR_STATUS_MAP.get(
                ErrorCode.INTERNAL_ERROR,
                st_status.HTTP_500_INTERNAL_SERVER_ERROR,
            ),
            content=DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.INTERNAL_ERROR,
                    message="Internal server error",
                ),
                provider="unknown",
                zone="",
                record_type="",
                record_name="",
                include_debug_info=include_debug,
                raw_input={},
                extra={"original_exception": str(exc)},
            ).model_dump(exclude_none=True),
        )

    errors = exc.errors()
    missing_fields: list[str] = []
    invalid_fields: list[str] = []

    for error in errors:
        field_path = ".".join(
            str(loc) for loc in error["loc"] if loc not in {"query", "body"}
        )
        if error["type"] == "missing":
            missing_fields.append(f"'{field_path}'")
        else:
            invalid_fields.append(f"'{field_path}': {error['msg']}")

    # Build message
    messages: list[str] = []
    if missing_fields:
        messages.append(f"Missing required fields: {', '.join(missing_fields)}.")
    if invalid_fields:
        messages.append(f"Invalid fields: {'; '.join(invalid_fields)}.")

    message = ". ".join(messages) if messages else "Validation error"
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(
        '[request] Validation error. Path: "%s", Method: "%s", Client IP: "%s", '
        'Missing Fields: "%s", Invalid Fields: "%s".',
        request.url.path,
        request.method,
        client_ip,
        ", ".join(missing_fields) if missing_fields else "N/A",
        "; ".join(invalid_fields) if invalid_fields else "N/A",
    )

    return JSONResponse(
        status_code=ERROR_STATUS_MAP.get(
            ErrorCode.VALIDATION_ERROR,
            st_status.HTTP_400_BAD_REQUEST,
        ),
        content=DDNSResponse.error(
            errors=ErrorModel(
                code=ErrorCode.VALIDATION_ERROR,
                message=message,
            ),
            provider="unknown",
            zone="",
            record_type="",
            record_name="",
        ).model_dump(exclude_none=True),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> Response:
    """
    Handle uncaught exceptions with consistent JSON responses.

    This is a fallback handler that catches any exception not handled by
    more specific handlers, ensuring the API always returns a consistent
    DDNSResponse format.

    This handler is particularly important after the DDNSResponse factory
    method refactoring, as ``DDNSResponse.success()`` and ``DDNSResponse.error()``
    may raise ``ValueError`` when required parameters are missing.

    Parameters
    ----------
    request : Request
        The FastAPI request object.
    exc : Exception
        The uncaught exception.

    Returns
    -------
    Response
        A JSON response with error status and INTERNAL_ERROR code.

    Notes
    -----
    This handler uses direct DDNSResponse construction (not the factory method)
    to avoid potential infinite recursion if the factory methods themselves
    are the source of the error. Internal details are hidden from the response
    and only included in debug info when enabled.
    """
    logger.exception('Unhandled exception: "%s".', exc)

    include_debug = _should_include_debug_info(request)

    # Build debug info if enabled
    # IMPORTANT: Use direct DebugInfo construction here, NOT through factory method
    # to avoid potential infinite recursion if the factory method itself
    # is the source of the exception
    debug_info: DebugInfo | None = None
    if include_debug:
        debug_info = DebugInfo(
            raw_input={},
            extra={
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
            },
        )

    # IMPORTANT: Use direct construction here, NOT DDNSResponse.error()
    # This avoids potential infinite recursion if the factory method itself
    # is the source of the exception
    error_response = DDNSResponse(
        status="error",
        action=None,
        upstream_called=False,
        provider="unknown",
        record=RecordInfo(zone="", type="", name=""),
        result=None,
        warnings=[],
        errors=[
            ErrorModel(
                code=ErrorCode.INTERNAL_ERROR,
                message="Internal server error",
            ),
        ],
        meta=ResponseMeta(),
        debug=debug_info,
    )

    return JSONResponse(
        status_code=st_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(exclude_none=True),
    )


# =============================================================================
# API Endpoints
# =============================================================================


async def upsert_ddns_record(
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    request: Request,
    body: UpsertRequest | None = None,
    value: Annotated[str | None, Query()] = None,
    ttl: Annotated[int | None, Query(ge=1, le=86400)] = None,
    comment: Annotated[str | None, Query(max_length=500)] = None,
    proxied: Annotated[bool | None, Query()] = None,
) -> Response:
    """
    Upsert (create or update) a DNS record.

    Path Parameters
    ---------------
    provider : str
        The DNS provider (e.g. 'cloudflare', 'aliyun', 'tencent').
        Must be a valid value from the `DNSProvider` enum.
    zone : str
        The DNS zone (root domain, e.g., "example.com").
    record_type : str
        The record type: A, AAAA, CNAME, TXT (case-insensitive).
    record : str
        The host record name (e.g., "home", "@", "*").

    Body Parameters (JSON, preferred)
    ----------------------------------
    value : str
        The desired record value (required).
    ttl : int | None
        The desired TTL in seconds (optional).
    comment : str | None
        The desired comment (optional).
    proxied : bool | None
        The Cloudflare proxy status (CF only, A/AAAA/CNAME).

    Query Parameters (fallback if no body)
    --------------------------------------
    Same as body parameters.

    Returns
    -------
    DDNSResponse
        The operation result.
    """
    # Access config from app.state
    config: Config = request.app.state.config

    provider_lower = provider.lower()

    # Validate provider
    try:
        provider_enum = DNSProvider(provider_lower)
    except ValueError:
        client_ip = request.client.host if request.client else "unknown"
        logger.debug(
            '[request: upsert] Invalid provider. Path: "%s", Method: "%s", Client IP: "%s", Provider: "%s".',
            request.url.path,
            request.method,
            client_ip,
            provider,
        )
        return JSONResponse(
            status_code=ERROR_STATUS_MAP.get(
                ErrorCode.INVALID_PROVIDER,
                st_status.HTTP_400_BAD_REQUEST,
            ),
            content=DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.INVALID_PROVIDER,
                    message=(
                        f"Invalid provider: {provider}. "
                        f"Must be one of: {', '.join([p.value for p in DNSProvider])}."
                    ),
                    field="provider",
                ),
                provider=provider_lower,
                zone=zone,
                record_type=record_type.upper(),
                record_name=record,
            ).model_dump(exclude_none=True),
        )

    # Get provider instance
    provider_instance = _providers.get(provider_enum)
    if provider_instance is None:
        client_ip = request.client.host if request.client else "unknown"
        logger.error(
            '[request: upsert] Provider not initialized. Path: "%s", Method: "%s", Client IP: "%s", Provider: "%s".',
            request.url.path,
            request.method,
            client_ip,
            provider,
        )
        return JSONResponse(
            status_code=ERROR_STATUS_MAP.get(
                ErrorCode.INTERNAL_ERROR,
                st_status.HTTP_500_INTERNAL_SERVER_ERROR,
            ),
            content=DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.INTERNAL_ERROR,
                    message="Internal server error",
                ),
                provider=provider_lower,
                zone=zone,
                record_type=record_type.upper(),
                record_name=record,
                include_debug_info=config.response.include_debug_info,
                raw_input={
                    "provider": provider,
                    "zone": zone,
                    "record_type": record_type,
                    "record": record,
                },
                extra={"reason": f"Provider {provider} not initialized"},
            ).model_dump(exclude_none=True),
        )

    # Determine value source (body preferred over query)
    # If both body and query have values, log a debug warning and ignore query
    api_warnings: list[WarningModel] = []
    final_value: str | None = None
    final_ttl: int | None = None
    final_comment: str | None = None
    final_proxied: bool | None = None

    if body is not None:
        # Check for ignored query parameters
        ignored_params: list[str] = []
        if value is not None:
            ignored_params.append("value")
        if ttl is not None:
            ignored_params.append("ttl")
        if comment is not None:
            ignored_params.append("comment")
        if proxied is not None:
            ignored_params.append("proxied")

        if ignored_params:
            logger.debug(
                "Query parameters ignored due to body: %s",
                ", ".join(ignored_params),
            )
            api_warnings.append(
                WarningModel(
                    code=WarningCode.QUERY_IGNORED_DUE_TO_BODY,
                    message=f"Query parameters ignored: {', '.join(ignored_params)}",
                    details={"ignored_params": ignored_params},
                ),
            )

        final_value = body.value
        final_ttl = body.ttl
        final_comment = body.comment
        final_proxied = body.proxied
    else:
        final_value = value
        final_ttl = ttl
        final_comment = comment
        final_proxied = proxied

    # Validate value
    # if not final_value:
    #     return JSONResponse(
    #         status_code=ERROR_STATUS_MAP.get(
    #             ErrorCode.VALIDATION_ERROR,
    #             st_status.HTTP_400_BAD_REQUEST,
    #         ),
    #         content=DDNSResponse.error(
    #             errors=ErrorModel(
    #                 code=ErrorCode.VALIDATION_ERROR,
    #                 message="Missing required field: value",
    #                 field="value",
    #             ),
    #             provider=provider_lower,
    #             zone=zone,
    #             record_type=record_type.upper(),
    #             record_name=record,
    #             warnings=api_warnings,
    #         ).model_dump(exclude_none=True),
    #     )

    # Validate value - raise RequestValidationError to unify error handling
    if not final_value:
        error_location = "body" if body is not None else "query"

        errors = [
            {
                "loc": (error_location, "value"),
                "msg": "Missing required field: 'value'.",
                "type": "missing",
            },
        ]

        raise RequestValidationError(errors=errors)

    # Extract credentials
    credentials = extract_credentials_from_header(provider_enum, request)

    # Log request
    # Set to DEBUG level here because uvicorn already logs request info at INFO level
    logger.debug(
        '[request: upsert] PUT /v1/ddns/%s/%s/%s/%s, Value: "%s".',
        provider_lower,
        zone,
        record_type,
        record,
        final_value,
    )

    # Call service layer with config values
    response = await upsert_record_service(
        provider_instance=provider_instance,
        provider=provider_lower,
        zone=zone,
        record_type=record_type,
        record=record,
        value=final_value,
        ttl=final_ttl,
        comment=final_comment,
        proxied=final_proxied,
        credentials=credentials,
        dedupe_cache=request.app.state.dedupe_cache,
        dedupe_config=config.dedupe if config.dedupe.enabled else None,
        timeout_sec=config.retry.request_timeout_sec,
        include_debug_info=config.response.include_debug_info,
    )

    # Merge API-layer warnings into response
    if api_warnings:
        response.warnings = api_warnings + response.warnings

    # Determine HTTP status code using error code mapping
    status_code = _get_http_status_code(response)

    # Build response headers
    headers: dict[str, str] = {}

    # Add Retry-After header for singleflight timeout (504)
    if status_code == st_status.HTTP_504_GATEWAY_TIMEOUT and config.dedupe.enabled:
        retry_after = math.ceil(config.dedupe.singleflight_lease_sec)
        headers["Retry-After"] = str(retry_after)

    logger.info(
        '[response: upsert] Status: "%s", Action: "%s", Upstream Called: "%s".',
        response.status,
        response.action or "N/A",
        response.upstream_called,
    )

    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        status_code=status_code,
        headers=headers if headers else None,
    )


async def delete_ddns_record(
    provider: str,
    zone: str,
    record_type: str,
    record: str,
    request: Request,
) -> Response:
    """
    Delete a DNS record.

    Path Parameters
    ---------------
    provider : str
        The DNS provider (e.g. 'cloudflare', 'aliyun', 'tencent').
        Must be a valid value from the `DNSProvider` enum.
    zone : str
        The DNS zone (root domain, e.g., "example.com").
    record_type : str
        The record type: A, AAAA, CNAME, TXT (case-insensitive).
    record : str
        The host record name (e.g., "home", "@", "*").

    Returns
    -------
    DDNSResponse
        The operation result.
    """
    # Access config from app.state
    config: Config = request.app.state.config

    provider_lower = provider.lower()

    # Validate provider
    try:
        provider_enum = DNSProvider(provider_lower)
    except ValueError:
        client_ip = request.client.host if request.client else "unknown"
        logger.debug(
            '[request: delete] Invalid provider. Path: "%s", Method: "%s", Client IP: "%s", Provider: "%s".',
            request.url.path,
            request.method,
            client_ip,
            provider,
        )
        return JSONResponse(
            status_code=ERROR_STATUS_MAP.get(
                ErrorCode.INVALID_PROVIDER,
                st_status.HTTP_400_BAD_REQUEST,
            ),
            content=DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.INVALID_PROVIDER,
                    message=(
                        f"Invalid provider: {provider}. "
                        f"Must be one of: {', '.join([p.value for p in DNSProvider])}"
                    ),
                    field="provider",
                ),
                provider=provider_lower,
                zone=zone,
                record_type=record_type.upper(),
                record_name=record,
            ).model_dump(exclude_none=True),
        )

    # Get provider instance
    provider_instance = _providers.get(provider_enum)
    if provider_instance is None:
        client_ip = request.client.host if request.client else "unknown"
        logger.error(
            '[request: delete] Provider not initialized. Path: "%s", Method: "%s", Client IP: "%s", Provider: "%s".',
            request.url.path,
            request.method,
            client_ip,
            provider,
        )
        return JSONResponse(
            status_code=ERROR_STATUS_MAP.get(
                ErrorCode.INTERNAL_ERROR,
                st_status.HTTP_500_INTERNAL_SERVER_ERROR,
            ),
            content=DDNSResponse.error(
                errors=ErrorModel(
                    code=ErrorCode.INTERNAL_ERROR,
                    message="Internal server error",
                ),
                provider=provider_lower,
                zone=zone,
                record_type=record_type.upper(),
                record_name=record,
                include_debug_info=config.response.include_debug_info,
                raw_input={
                    "provider": provider,
                    "zone": zone,
                    "record_type": record_type,
                    "record": record,
                },
                extra={"reason": f"Provider {provider} not initialized"},
            ).model_dump(exclude_none=True),
        )

    # Extract credentials
    credentials = extract_credentials_from_header(provider_enum, request)

    # Check for ignored body/query parameters and generate warnings
    api_warnings: list[WarningModel] = []

    # Check for body (DELETE should not accept body)
    # Since DELETE doesn't use body, it's safe to read it to check if it exists
    content_type = request.headers.get("content-type", "").lower()
    if content_type.startswith("application/json"):
        # Try to read body to check if it's non-empty
        try:
            body_bytes = await request.body()
            if body_bytes:
                # Try to parse as JSON to get ignored keys for details
                try:
                    body_data = json.loads(body_bytes.decode())
                    if body_data:
                        ignored_keys = (
                            list(body_data.keys())
                            if isinstance(body_data, dict)
                            else []
                        )
                        api_warnings.append(
                            WarningModel(
                                code=WarningCode.DELETE_IGNORES_BODY_PARAMS,
                                message="DELETE request ignores body parameters. Only path parameters are used.",
                                field="body",
                                details={"ignored_keys": ignored_keys}
                                if ignored_keys
                                else None,
                            ),
                        )
                    else:
                        # Empty dict/list, still warn
                        api_warnings.append(
                            WarningModel(
                                code=WarningCode.DELETE_IGNORES_BODY_PARAMS,
                                message="DELETE request ignores body parameters. Only path parameters are used.",
                                field="body",
                            ),
                        )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # If body is not valid JSON, still warn about non-empty body
                    api_warnings.append(
                        WarningModel(
                            code=WarningCode.DELETE_IGNORES_BODY_PARAMS,
                            message="DELETE request ignores body parameters. Only path parameters are used.",
                            field="body",
                        ),
                    )
        except Exception as exc:  # noqa: BLE001
            # If reading body fails, skip warning (shouldn't happen in normal flow)
            client_ip = request.client.host if request.client else "unknown"
            logger.debug(
                "[request: delete] Failed to read request body. "
                'Path: "%s", Method: "%s", Client IP: "%s", Error: "%s".',
                request.url.path,
                request.method,
                client_ip,
                f"{type(exc).__name__}: {exc}",
            )

    # Check for query parameters (DELETE should not use query)
    query_params = dict(request.query_params)
    # Filter out non-business query params (e.g., format=plain for response format)
    business_query_params = {
        k: v
        for k, v in query_params.items()
        if k not in {"format"}  # format is allowed for response format negotiation
    }
    if business_query_params:
        api_warnings.append(
            WarningModel(
                code=WarningCode.DELETE_IGNORES_QUERY_PARAMS,
                message="DELETE request ignores query parameters. Only path parameters are used.",
                field="query",
                details={"ignored_params": list(business_query_params.keys())},
            ),
        )

    # Log request
    # Set to DEBUG level here because uvicorn already logs request info at INFO level
    logger.debug(
        "[request: delete] DELETE /v1/ddns/%s/%s/%s/%s.",
        provider_lower,
        zone,
        record_type,
        record,
    )

    # Call service layer with config values
    response = await delete_record_service(
        provider_instance=provider_instance,
        provider=provider_lower,
        zone=zone,
        record_type=record_type,
        record=record,
        credentials=credentials,
        dedupe_cache=request.app.state.dedupe_cache,
        dedupe_config=config.dedupe if config.dedupe.enabled else None,
        timeout_sec=config.retry.request_timeout_sec,
        include_debug_info=config.response.include_debug_info,
    )

    # Merge API-layer warnings into response
    if api_warnings:
        response.warnings = api_warnings + response.warnings

    # Determine HTTP status code using error code mapping
    status_code = _get_http_status_code(response)

    # Build response headers
    headers: dict[str, str] = {}

    # Add Retry-After header for singleflight timeout (504)
    if status_code == st_status.HTTP_504_GATEWAY_TIMEOUT and config.dedupe.enabled:
        retry_after = math.ceil(config.dedupe.singleflight_lease_sec)
        headers["Retry-After"] = str(retry_after)

    logger.info(
        '[response: delete] Status: "%s", Action: "%s", Upstream Called: "%s".',
        response.status,
        response.action or "N/A",
        response.upstream_called,
    )

    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        status_code=status_code,
        headers=headers if headers else None,
    )


async def health() -> Response:
    """
    Health check endpoint.

    This endpoint is dynamically registered in lifespan() based on
    config.health.enabled.
    """
    return JSONResponse(content={"status": "ok"})
