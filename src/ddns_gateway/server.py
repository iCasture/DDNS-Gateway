"""
FastAPI server for DDNS Gateway.

This module provides the main API server with endpoints for DNS record operations.
Supports PUT (upsert) and DELETE methods with authentication.
"""

from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette import status as st_status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ddns_gateway.config import Config, load_config
from ddns_gateway.models import (
    DDNSResponse,
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
    Middleware for authentication.

    Intercepts requests to /v1/ddns/ endpoints to check:
    1. Authentication via Authorization header -> 401 if missing, 403 if invalid
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

        # Config may not be loaded during startup
        try:
            config = get_config()
        except RuntimeError:
            return await call_next(request)

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
                content=DDNSResponse(
                    status="error",
                    action=None,
                    upstream_called=False,
                    provider="unknown",
                    record=RecordInfo(zone="", type="", name=""),
                    result=None,
                    warnings=[],
                    errors=[
                        ErrorModel(
                            code=ErrorCode.MISSING_AUTH_TOKEN,
                            message="Missing authentication token",
                        ),
                    ],
                    meta=ResponseMeta(),
                    debug=None,
                ).model_dump(exclude_none=True),
            )
        if server_token not in config.auth.tokens:
            return JSONResponse(
                status_code=st_status.HTTP_403_FORBIDDEN,
                content=DDNSResponse(
                    status="error",
                    action=None,
                    upstream_called=False,
                    provider="unknown",
                    record=RecordInfo(zone="", type="", name=""),
                    result=None,
                    warnings=[],
                    errors=[
                        ErrorModel(
                            code=ErrorCode.INVALID_AUTH_TOKEN,
                            message="Invalid authentication token",
                        ),
                    ],
                    meta=ResponseMeta(),
                    debug=None,
                ).model_dump(exclude_none=True),
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

    # Dynamically register "/health" endpoint (GET method) if enabled
    if _config.health.enabled:
        _app.add_api_route("/health", health, methods=["GET"])

    logger.info(
        'DDNS Gateway starting on "%s:%d".',
        _config.server.host,
        _config.server.port,
    )

    yield

    logger.info("DDNS Gateway shutting down.")


app = FastAPI(
    title="DDNS Gateway",
    description="DDNS update service for RouterOS - bridges ROS scripts with DNS providers",
    version="0.2.0",
    lifespan=lifespan,
)

# Add middleware for authentication
app.add_middleware(AuthMiddleware)


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException) -> Response:
    """
    Handle HTTP exceptions with consistent JSON responses.

    Convert FastAPI's default {"detail": "..."} format to the unified
    API response format.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=DDNSResponse(
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
                    message=str(exc.detail),
                ),
            ],
            meta=ResponseMeta(),
            debug=None,
        ).model_dump(exclude_none=True),
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
        field_path = ".".join(
            str(loc) for loc in error["loc"] if loc not in {"query", "body"}
        )
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
        content=DDNSResponse(
            status="error",
            action=None,
            upstream_called=False,
            provider="unknown",
            record=RecordInfo(zone="", type="", name=""),
            result=None,
            warnings=[],
            errors=[
                ErrorModel(
                    code=ErrorCode.VALIDATION_ERROR,
                    message=message,
                ),
            ],
            meta=ResponseMeta(),
            debug=None,
        ).model_dump(exclude_none=True),
    )


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
    if not header_value:
        return {}

    auth_id, auth_secret = parse_upstream_auth(header_value)

    creds: dict[str, str] = {}

    if provider == DNSProvider.CLOUDFLARE:
        # Cloudflare only needs secret (token), id is ignored if provided
        if auth_secret:
            creds["secret"] = auth_secret
    elif provider in (DNSProvider.ALIYUN, DNSProvider.TENCENT):
        # Aliyun and Tencent use both id and secret
        if auth_id:
            creds["id"] = auth_id
        if auth_secret:
            creds["secret"] = auth_secret

    return creds


# =============================================================================
# API Endpoints
# =============================================================================


@app.put("/v1/ddns/{provider}/{zone}/{record_type}/{record}")
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
    provider_lower = provider.lower()

    # Validate provider
    try:
        provider_enum = DNSProvider(provider_lower)
    except ValueError:
        return JSONResponse(
            status_code=st_status.HTTP_400_BAD_REQUEST,
            content=DDNSResponse(
                status="error",
                action=None,
                upstream_called=False,
                provider=provider_lower,
                record=RecordInfo(zone=zone, type=record_type.upper(), name=record),
                result=None,
                warnings=[],
                errors=[
                    ErrorModel(
                        code=ErrorCode.INVALID_PROVIDER,
                        message=(
                            f"Invalid provider: {provider}. "
                            f"Must be one of: {', '.join([p.value for p in DNSProvider])}."
                        ),
                        field="provider",
                    ),
                ],
                meta=ResponseMeta(),
                debug=None,
            ).model_dump(exclude_none=True),
        )

    # Get provider instance
    provider_instance = _providers.get(provider_enum)
    if provider_instance is None:
        return JSONResponse(
            status_code=st_status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=DDNSResponse(
                status="error",
                action=None,
                upstream_called=False,
                provider=provider_lower,
                record=RecordInfo(zone=zone, type=record_type.upper(), name=record),
                result=None,
                warnings=[],
                errors=[
                    ErrorModel(
                        code=ErrorCode.INTERNAL_ERROR,
                        message=f"Provider {provider} not initialized",
                    ),
                ],
                meta=ResponseMeta(),
                debug=None,
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
    if not final_value:
        return JSONResponse(
            status_code=st_status.HTTP_400_BAD_REQUEST,
            content=DDNSResponse(
                status="error",
                action=None,
                upstream_called=False,
                provider=provider_lower,
                record=RecordInfo(zone=zone, type=record_type.upper(), name=record),
                result=None,
                warnings=api_warnings,
                errors=[
                    ErrorModel(
                        code=ErrorCode.VALIDATION_ERROR,
                        message="Missing required field: value",
                        field="value",
                    ),
                ],
                meta=ResponseMeta(),
                debug=None,
            ).model_dump(exclude_none=True),
        )

    # Extract credentials
    credentials = extract_credentials_from_header(provider_enum, request)

    # Log request
    logger.info(
        "[request] PUT /v1/ddns/%s/%s/%s/%s value=%s",
        provider_lower,
        zone,
        record_type,
        record,
        final_value,
    )

    # Call service layer
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
    )

    # Merge API-layer warnings into response
    if api_warnings:
        response.warnings = api_warnings + response.warnings

    # Determine HTTP status code
    status_code = (
        st_status.HTTP_200_OK
        if response.status == "success"
        else st_status.HTTP_400_BAD_REQUEST
    )

    logger.info(
        "[response] status=%s action=%s upstream_called=%s",
        response.status,
        response.action,
        response.upstream_called,
    )

    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        status_code=status_code,
    )


@app.delete("/v1/ddns/{provider}/{zone}/{record_type}/{record}")
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
    provider_lower = provider.lower()

    # Validate provider
    try:
        provider_enum = DNSProvider(provider_lower)
    except ValueError:
        return JSONResponse(
            status_code=st_status.HTTP_400_BAD_REQUEST,
            content=DDNSResponse(
                status="error",
                action=None,
                upstream_called=False,
                provider=provider_lower,
                record=RecordInfo(zone=zone, type=record_type.upper(), name=record),
                result=None,
                warnings=[],
                errors=[
                    ErrorModel(
                        code=ErrorCode.INVALID_PROVIDER,
                        message=(
                            f"Invalid provider: {provider}. "
                            f"Must be one of: {', '.join([p.value for p in DNSProvider])}"
                        ),
                        field="provider",
                    ),
                ],
                meta=ResponseMeta(),
                debug=None,
            ).model_dump(exclude_none=True),
        )

    # Get provider instance
    provider_instance = _providers.get(provider_enum)
    if provider_instance is None:
        return JSONResponse(
            status_code=st_status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=DDNSResponse(
                status="error",
                action=None,
                upstream_called=False,
                provider=provider_lower,
                record=RecordInfo(zone=zone, type=record_type.upper(), name=record),
                result=None,
                warnings=[],
                errors=[
                    ErrorModel(
                        code=ErrorCode.INTERNAL_ERROR,
                        message=f"Provider {provider} not initialized",
                    ),
                ],
                meta=ResponseMeta(),
                debug=None,
            ).model_dump(exclude_none=True),
        )

    # Extract credentials
    credentials = extract_credentials_from_header(provider_enum, request)

    # Log request
    logger.info(
        "[request] DELETE /v1/ddns/%s/%s/%s/%s",
        provider_lower,
        zone,
        record_type,
        record,
    )

    # Call service layer
    response = await delete_record_service(
        provider_instance=provider_instance,
        provider=provider_lower,
        zone=zone,
        record_type=record_type,
        record=record,
        credentials=credentials,
    )

    # Determine HTTP status code
    status_code = (
        st_status.HTTP_200_OK
        if response.status == "success"
        else st_status.HTTP_400_BAD_REQUEST
    )

    logger.info(
        "[response] status=%s action=%s upstream_called=%s",
        response.status,
        response.action,
        response.upstream_called,
    )

    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        status_code=status_code,
    )


# Note: Unlike the routes above, this endpoint is dynamically registered
# in lifespan() based on config.health.enabled.
async def health() -> Response:
    """Health check endpoint."""
    return JSONResponse(content={"status": "ok"})
