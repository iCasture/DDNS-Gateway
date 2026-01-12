"""
Data models for DDNS Gateway.

This module defines the core data structures used throughout the application,
including request/response models, enumerations for providers and record types,
and configuration models.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field
from starlette import status as st_status


class DNSProvider(StrEnum):
    """
    Supported DNS providers.

    Attributes
    ----------
    CLOUDFLARE : str
        CloudFlare DNS service.
    ALIYUN : str
        Alibaba Cloud DNS (alidns) service.
    TENCENT : str
        Tencent Cloud DNSPod service (China mainland only).
    """

    CLOUDFLARE = "cloudflare"
    ALIYUN = "aliyun"
    TENCENT = "tencent"


class RecordType(StrEnum):
    """
    Supported DNS record types.

    Attributes
    ----------
    A : str
        IPv4 address record.
    AAAA : str
        IPv6 address record.
    CNAME : str
        Canonical name (alias) record.
    TXT : str
        Text record.
    """

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"


class UpdateRequest(BaseModel):
    """
    DNS record update request model.

    Attributes
    ----------
    provider : DNSProvider
        The DNS provider to use.
    zone : str
        The DNS zone (root domain name, e.g., "example.com").
    record : str
        The host record name (e.g., "home", "@", "www").
    record_type : RecordType
        The type of DNS record (A, AAAA, CNAME, TXT).
    value : str
        The record value (IP address, target domain, text content, etc.).
    ttl : int | None
        Time to live in seconds, or None to use provider default.
    comment : str | None
        Optional comment/remark for the record.
    """

    provider: DNSProvider
    zone: str = Field(..., min_length=1, description="DNS zone (root domain name)")
    record: str = Field(..., min_length=1, description="Host record name")
    record_type: RecordType = Field(..., alias="type")
    value: str = Field(..., min_length=1, description="Record value")
    ttl: int | None = Field(default=None, ge=1, le=86400, description="TTL in seconds")
    comment: str | None = Field(
        default=None,
        max_length=500,
        description="Optional comment",
    )

    model_config = {"populate_by_name": True}


class WarningModel(BaseModel):
    """
    Warning message for non-critical issues.

    Attributes
    ----------
    code : str
        Machine-readable warning code.
    message : str
        Human-readable warning message.
    """

    code: str
    message: str


class ProviderMetadata(BaseModel):
    """
    Provider-specific metadata returned after an update.

    Attributes
    ----------
    record_id : str | None
        The DNS record ID from the provider.
    request_id : str | None
        The request ID from the provider API.
    zone_id : str | None
        The zone ID (CloudFlare specific).
    extra : dict[str, str] | None
        Additional provider-specific metadata.
    """

    record_id: str | None = None
    request_id: str | None = None
    zone_id: str | None = None
    extra: dict[str, str] | None = None


class ResponseData(BaseModel):
    """
    Data payload in the update response.

    Attributes
    ----------
    provider : str
        The DNS provider used.
    zone : str
        The DNS zone (root domain name).
    record : str
        The host record name.
    fqdn : str
        The fully qualified domain name.
    type : str
        The record type (A, AAAA, CNAME, TXT).
    value : str
        The current record value.
    ttl : int | None
        The TTL value.
    previous_value : str | None
        The previous record value (only for action=updated).
    """

    provider: str
    zone: str
    record: str
    fqdn: str
    type: str
    value: str
    ttl: int | None
    previous_value: str | None = None


class UpdateResponse(BaseModel):
    """
    DNS record update response model.

    This response format is designed to be compatible with RouterOS scripts,
    which cannot parse JSON. ROS can check for success by looking for
    the string '"status":"success"' in the response body.

    Attributes
    ----------
    status : Literal["success", "error"]
        The overall status of the operation.
    code : int
        HTTP-like status code.
    message : str
        Human-readable message describing the result.
    action : Literal["created", "updated", "unchanged"] | None
        The action taken (None for errors).
    data : ResponseData | None
        The response data payload (None for errors).
    provider_metadata : ProviderMetadata | None
        Provider-specific metadata.
    warnings : list[Warning]
        List of non-critical warnings.
    """

    status: Literal["success", "error"]
    code: int
    message: str
    action: Literal["created", "updated", "unchanged"] | None = None
    data: ResponseData | None = None
    provider_metadata: ProviderMetadata | None = None
    warnings: list[WarningModel] = Field(default_factory=list)

    @classmethod
    def success(
        cls,
        message: str,
        action: Literal["created", "updated", "unchanged"],
        data: ResponseData,
        provider_metadata: ProviderMetadata | None = None,
        warnings: list[WarningModel] | None = None,
    ) -> UpdateResponse:
        """
        Create a successful response.

        Parameters
        ----------
        message : str
            Human-readable success message.
        action : Literal["created", "updated", "unchanged"]
            The action that was taken.
        data : ResponseData
            The response data payload.
        provider_metadata : ProviderMetadata | None, optional
            Provider-specific metadata.
        warnings : list[WarningModel] | None, optional
            List of warnings.

        Returns
        -------
        UpdateResponse
            A success response instance.
        """
        return cls(
            status="success",
            code=st_status.HTTP_200_OK,
            message=message,
            action=action,
            data=data,
            provider_metadata=provider_metadata,
            warnings=warnings or [],
        )

    @classmethod
    def error(
        cls,
        code: int,
        message: str,
        warnings: list[WarningModel] | None = None,
    ) -> UpdateResponse:
        """
        Create an error response.

        Parameters
        ----------
        code : int
            HTTP-like error code.
        message : str
            Human-readable error message.
        warnings : list[WarningModel] | None, optional
            List of warnings.

        Returns
        -------
        UpdateResponse
            An error response instance.
        """
        return cls(
            status="error",
            code=code,
            message=message,
            warnings=warnings or [],
        )
