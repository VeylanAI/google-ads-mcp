#!/usr/bin/env python

# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Common utilities used by the MCP server."""

from __future__ import annotations

from dataclasses import dataclass
from contextvars import ContextVar
import hashlib
import importlib.resources
import json
import logging
import os
from typing import Any, Mapping, Optional

import google.auth
import proto
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.util import get_nested_attr
from google.ads.googleads.v21.services.services.google_ads_service import (
    GoogleAdsServiceClient,
)

from ads_mcp import request_context
from ads_mcp.mcp_header_interceptor import MCPHeaderInterceptor

# filename for generated field information used by search
_GAQL_FILENAME = "gaql_resources.json"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Read-only scope for Analytics Admin API and Analytics Data API.
_READ_ONLY_ADS_SCOPE = "https://www.googleapis.com/auth/adwords"


@dataclass(frozen=True)
class _ClientSpec:
    developer_token: Optional[str]
    login_customer_id: Optional[str]
    credential_fingerprint: str


@dataclass
class _ClientCache:
    spec: _ClientSpec
    client: GoogleAdsClient


_CLIENT_CACHE: ContextVar[Optional[_ClientCache]] = ContextVar(
    "ads_mcp_googleads_client_cache", default=None
)


def _current_environment() -> Mapping[str, Any] | None:
    return request_context.get_request_environment()


def _get_developer_token(environment: Mapping[str, Any] | None) -> Optional[str]:
    """Returns the developer token favoring request environment over process env."""
    if environment:
        developer_token = environment.get("developer_token")
        if isinstance(developer_token, str) and developer_token.strip():
            return developer_token.strip()

    developer_token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if developer_token is None:
        logger.warning(
            "GOOGLE_ADS_DEVELOPER_TOKEN not supplied in request environment or process env."
        )
    return developer_token


def _get_login_customer_id(
    environment: Mapping[str, Any] | None,
) -> Optional[str]:
    """Returns login customer id from request environment or process env."""
    if environment:
        login_customer_id = environment.get("login_customer_id")
        if isinstance(login_customer_id, str) and login_customer_id.strip():
            return login_customer_id.strip()

    return os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")


def _load_adc_dict(environment: Mapping[str, Any] | None) -> Optional[dict[str, Any]]:
    """Loads ADC (Application Default Credential) payload from the request environment."""
    if not environment:
        return None

    raw_adc = environment.get("adc")
    if isinstance(raw_adc, Mapping):
        return dict(raw_adc)

    raw_adc_json = environment.get("adc_json")
    if isinstance(raw_adc_json, str):
        try:
            return json.loads(raw_adc_json)
        except json.JSONDecodeError:
            logger.error(
                "adc_json payload could not be parsed; falling back to default credentials."
            )

    return None


def _create_credentials(
    environment: Mapping[str, Any] | None,
) -> google.auth.credentials.Credentials:
    """Builds Google credentials from the request environment or process defaults."""
    adc_payload = _load_adc_dict(environment)

    if adc_payload:
        credentials, _ = google.auth.load_credentials_from_dict(
            adc_payload, scopes=[_READ_ONLY_ADS_SCOPE]
        )
        return credentials

    credentials, _ = google.auth.default(scopes=[_READ_ONLY_ADS_SCOPE])
    return credentials


def _credentials_fingerprint(environment: Mapping[str, Any] | None) -> str:
    """Returns a fingerprint representing the current credential source."""
    adc_payload = _load_adc_dict(environment)
    if adc_payload is not None:
        serialized = json.dumps(adc_payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env_path:
        return f"path:{env_path}"

    return "default-adc"


def _current_client_spec(environment: Mapping[str, Any] | None) -> _ClientSpec:
    return _ClientSpec(
        developer_token=_get_developer_token(environment),
        login_customer_id=_get_login_customer_id(environment),
        credential_fingerprint=_credentials_fingerprint(environment),
    )


def _build_googleads_client(environment: Mapping[str, Any] | None) -> GoogleAdsClient:
    """Creates a GoogleAdsClient using the provided environment configuration."""
    spec = _current_client_spec(environment)
    credentials = _create_credentials(environment)
    client = GoogleAdsClient(
        credentials=credentials,
        developer_token=spec.developer_token,
        login_customer_id=spec.login_customer_id,
    )
    return client


def _get_googleads_client() -> GoogleAdsClient:
    """Fetches a Google Ads client scoped to the active request environment."""
    environment = _current_environment()
    cache_entry = _CLIENT_CACHE.get()

    desired_spec = _current_client_spec(environment)
    if cache_entry and cache_entry.spec == desired_spec:
        return cache_entry.client

    client = _build_googleads_client(environment)
    _CLIENT_CACHE.set(_ClientCache(spec=desired_spec, client=client))
    return client


def get_googleads_service(serviceName: str) -> GoogleAdsServiceClient:
    client = _get_googleads_client()
    return client.get_service(serviceName, interceptors=[MCPHeaderInterceptor()])


def get_googleads_type(typeName: str):
    client = _get_googleads_client()
    return client.get_type(typeName)


def format_output_value(value: Any) -> Any:
    if isinstance(value, proto.Enum):
        return value.name
    else:
        return value


def format_output_row(row: proto.Message, attributes):
    return {
        attr: format_output_value(get_nested_attr(row, attr)) for attr in attributes
    }


def get_gaql_resources_filepath():
    package_root = importlib.resources.files("ads_mcp")
    file_path = package_root.joinpath(_GAQL_FILENAME)
    return file_path
