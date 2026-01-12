"""
FastAPI server for DDNS Gateway.

This module provides the main API server with endpoints for updating DNS records.
Supports both GET and POST methods with optional authentication.
"""

from __future__ import annotations

import logging
import re
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette import status as st_status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ddns_gateway.config import Config, load_config
from ddns_gateway.models import (
    DNSProvider,
    RecordType,
    ResponseData,
    UpdateResponse,
)
from ddns_gateway.providers.aliyun import AliyunProvider
from ddns_gateway.providers.cloudflare import CloudFlareProvider
from ddns_gateway.providers.tencent import TencentProvider

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from typing import Final

    from ddns_gateway.providers.base import BaseDNSProvider


logger = logging.getLogger(__name__)

# Global config (set during startup)
_config: Config | None = None

# Provider instances
_providers: dict[DNSProvider, BaseDNSProvider] = {
    DNSProvider.CLOUDFLARE: CloudFlareProvider(),
    DNSProvider.ALIYUN: AliyunProvider(),
    DNSProvider.TENCENT: TencentProvider(),
}


def get_config() -> Config:
    """Get the current configuration."""
    if _config is None:
        msg = "Configuration not loaded"
        raise RuntimeError(msg)
    return _config


def set_preloaded_config(config: Config) -> None:
    """
    Inject a pre-loaded configuration into the server module.

    This allows the CLI entry point to pass the parsed configuration to the
    server instance, avoiding the need to re-parse command-line arguments
    during application startup (e.g. in the lifespan handler).

    Parameters
    ----------
    config : Config
        The configuration object to set.
    """
    global _config  # noqa: PLW0603
    _config = config


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware for authentication and method validation.

    Intercepts requests to /update before parameter validation to check:
    1. HTTP method enablement (GET/POST) -> 405 if disabled
    2. Authentication via Authorization header -> 401 if missing, 403 if invalid
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process the request through auth/method validation."""
        # Only apply to /update path
        if request.url.path != "/update":
            return await call_next(request)

        # Config may not be loaded during startup
        try:
            config = get_config()
        except RuntimeError:
            return await call_next(request)

        method = request.method

        # Check method enablement
        if method == "GET" and not config.methods.get_enabled:
            return JSONResponse(
                status_code=st_status.HTTP_405_METHOD_NOT_ALLOWED,
                content={
                    "status": "error",
                    "code": st_status.HTTP_405_METHOD_NOT_ALLOWED,
                    "message": "GET method is disabled",
                },
            )
        if method == "POST" and not config.methods.post_enabled:
            return JSONResponse(
                status_code=st_status.HTTP_405_METHOD_NOT_ALLOWED,
                content={
                    "status": "error",
                    "code": st_status.HTTP_405_METHOD_NOT_ALLOWED,
                    "message": "POST method is disabled",
                },
            )

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
            return JSONResponse(
                status_code=st_status.HTTP_401_UNAUTHORIZED,
                content={
                    "status": "error",
                    "code": st_status.HTTP_401_UNAUTHORIZED,
                    "message": "Missing authentication token",
                },
            )
        if server_token not in config.auth.tokens:
            return JSONResponse(
                status_code=st_status.HTTP_403_FORBIDDEN,
                content={
                    "status": "error",
                    "code": st_status.HTTP_403_FORBIDDEN,
                    "message": "Invalid authentication token",
                },
            )

        return await call_next(request)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    global _config  # noqa: PLW0603

    # If config was not set by CLI (e.g., running via uvicorn directly),
    # load it here
    if _config is None:
        _config = load_config()

    # Dynamically register "/health"  endpoint (GET method) if enabled
    if _config.health.enabled:
        _app.add_api_route("/health", health, methods=["GET"])

    methods = []
    if _config.methods.get_enabled:
        methods.append("GET")
    if _config.methods.post_enabled:
        methods.append("POST")
    method_label = "Method" if len(methods) == 1 else "Methods"

    logger.info(
        'DDNS Gateway starting on "%s:%d" (%s: "%s").',
        _config.server.host,
        _config.server.port,
        method_label,
        ", ".join(methods),
    )

    yield

    logger.info("DDNS Gateway shutting down.")


app = FastAPI(
    title="DDNS Gateway",
    description="DDNS update service for RouterOS - bridges ROS scripts with DNS providers",
    version="0.1.0",
    lifespan=lifespan,
)

# Add middleware for auth and method validation
app.add_middleware(AuthMiddleware)


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException) -> Response:
    """
    Handle HTTP exceptions with consistent JSON responses.

    Convert FastAPI's default {"detail": "..."} format to the unified
    API response format {"status": "error", "code": ..., "message": "..."}.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "code": exc.status_code,
            "message": exc.detail,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
) -> Response:
    """
    Handle validation errors with consistent JSON responses.

    Convert FastAPI's validation error format to the unified API response format,
    listing all missing or invalid fields in the message.
    """
    errors = exc.errors()
    missing_fields: list[str] = []
    invalid_fields: list[str] = []

    for error in errors:
        field_path = ".".join(str(loc) for loc in error["loc"] if loc != "query")
        if error["type"] == "missing":
            missing_fields.append(field_path)
        else:
            invalid_fields.append(f"{field_path}: {error['msg']}")

    # Build message
    messages: list[str] = []
    if missing_fields:
        messages.append(f"Missing required fields: {', '.join(missing_fields)}")
    if invalid_fields:
        messages.append(f"Invalid fields: {'; '.join(invalid_fields)}")

    message = ". ".join(messages) if messages else "Validation error"

    return JSONResponse(
        status_code=st_status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "status": "error",
            "code": st_status.HTTP_422_UNPROCESSABLE_CONTENT,
            "message": message,
        },
    )


class UpdateParams(BaseModel):
    """
    Query/body parameters for the update endpoint.

    For GET requests: These fields are parsed from query parameters.
    For POST requests: These fields are parsed from the JSON body.
    """

    provider: DNSProvider
    zone: str = Field(..., min_length=1)
    record: str = Field(..., min_length=1)
    type: RecordType
    value: str = Field(..., min_length=1)
    ttl: int | None = Field(default=None, ge=1, le=86400)
    comment: str | None = Field(default=None, max_length=500)


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
                (?P<q1>["'])(?P<id1>(?:(?!(?P=q1)).)*)(?P=q1)   # quoted
                |
                (?P<id1_nq>[^,\s]+)                             # unquoted
            )
            \s*,\s*
            secret\s*=\s*
            (?:
                (?P<q2>["'])(?P<secret1>(?:(?!(?P=q2)).)*)(?P=q2)  # quoted
                |
                (?P<secret1_nq>[^,\s]+)                            # unquoted
            )
            |
            # Pattern 2: secret first, id optional
            secret\s*=\s*
            (?:
                (?P<q3>["'])(?P<secret2>(?:(?!(?P=q3)).)*)(?P=q3)  # quoted
                |
                (?P<secret2_nq>[^,\s]+)                            # unquoted
            )
            (?:
                \s*,\s*
                id\s*=\s*
                (?:
                    (?P<q4>["'])(?P<id2>(?:(?!(?P=q4)).)*)(?P=q4)  # quoted
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
        The DNS provider type.
    request : Request
        The FastAPI request object.

    Returns
    -------
    dict[str, str]
        Credentials dictionary with provider-specific keys.
    """
    header_value = request.headers.get("x-upstream-authorization", "")
    if not header_value:
        return {}

    auth_id, auth_secret = parse_upstream_auth(header_value)

    creds: dict[str, str] = {}

    if provider == DNSProvider.CLOUDFLARE:
        # Cloudflare only needs secret (token), id is ignored if provided
        if auth_secret:
            creds["cf_token"] = auth_secret
    elif provider == DNSProvider.ALIYUN:
        if auth_id:
            creds["ali_access_key_id"] = auth_id
        if auth_secret:
            creds["ali_access_key_secret"] = auth_secret
    elif provider == DNSProvider.TENCENT:
        if auth_id:
            creds["tc_secret_id"] = auth_id
        if auth_secret:
            creds["tc_secret_key"] = auth_secret

    return creds


async def process_update(params: UpdateParams, request: Request) -> UpdateResponse:
    """
    Process a DNS update request.

    Parameters
    ----------
    params : UpdateParams
        Request parameters.
    request : Request
        The FastAPI request object (for reading headers).

    Returns
    -------
    UpdateResponse
        The response to send to the client.
    """
    start_time = time.monotonic()

    # Log request (credentials masked by logging filter)
    logger.info(
        "[request] provider=%s zone=%s record=%s type=%s value=%s",
        params.provider,
        params.zone,
        params.record,
        params.type,
        params.value,
    )

    # Get provider
    provider = _providers.get(params.provider)
    if provider is None:
        return UpdateResponse.error(
            st_status.HTTP_400_BAD_REQUEST,
            f"Unknown provider: {params.provider}",
        )

    # Extract credentials from header
    credentials = extract_credentials_from_header(params.provider, request)

    # Call provider
    result = await provider.update_record(
        zone=params.zone,
        record=params.record,
        record_type=params.type,
        value=params.value,
        ttl=params.ttl,
        credentials=credentials,
        comment=params.comment,
    )

    duration = time.monotonic() - start_time

    if result.success:
        # Build FQDN
        fqdn = provider.build_fqdn(params.zone, params.record)

        # Build response data
        data = ResponseData(
            provider=params.provider.value,
            zone=params.zone,
            record=params.record,
            fqdn=fqdn,
            type=params.type.value,
            value=params.value,
            ttl=params.ttl,
            previous_value=result.previous_value,
        )

        logger.info(
            "[response] status=success action=%s duration=%.2fs",
            result.action,
            duration,
        )

        return UpdateResponse.success(
            message=result.message,
            action=result.action,  # type: ignore[arg-type]
            data=data,
            provider_metadata=result.to_metadata(),
            warnings=result.warnings,
        )
    logger.warning(
        "[response] status=error message=%s duration=%.2fs",
        result.message,
        duration,
    )

    return UpdateResponse.error(
        code=st_status.HTTP_400_BAD_REQUEST,
        message=result.message,
        warnings=result.warnings,
    )


@app.get("/update")
async def update_get(
    request: Request,
    provider: Annotated[DNSProvider, Query()],
    zone: Annotated[str, Query(min_length=1)],
    record: Annotated[str, Query(min_length=1)],
    record_type: Annotated[RecordType, Query(alias="type")],
    value: Annotated[str, Query(min_length=1)],
    ttl: Annotated[int | None, Query(ge=1, le=86400)] = None,
    comment: Annotated[str | None, Query(max_length=500)] = None,
) -> Response:
    """
    Update a DNS record (GET method).

    This endpoint is designed for easy use with RouterOS /tool fetch.
    Record details must be provided as query parameters.
    Credentials (server token & provider keys) are passed via HTTP headers.
    """
    # Method enablement and auth are checked by AuthMiddleware
    params = UpdateParams(
        provider=provider,
        zone=zone,
        record=record,
        type=record_type,
        value=value,
        ttl=ttl,
        comment=comment,
    )

    response = await process_update(params, request)

    status_code = response.code if response.status == "error" else st_status.HTTP_200_OK
    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        status_code=status_code,
    )


@app.post("/update")
async def update_post(request: Request, params: UpdateParams) -> Response:
    """
    Update a DNS record (POST method).

    Record details must be provided in the JSON body.
    Content-Type header must be set to "application/json".
    Credentials (server token & provider keys) are passed via HTTP headers.
    """
    # Method enablement and auth are checked by AuthMiddleware
    response = await process_update(params, request)

    status_code = response.code if response.status == "error" else st_status.HTTP_200_OK
    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        status_code=status_code,
    )


# Note: Unlike the routes above, this endpoint is dynamically registered
# in lifespan() based on config.health.enabled.
async def health() -> Response:
    """Health check endpoint."""
    return JSONResponse(content={"status": "ok"})
