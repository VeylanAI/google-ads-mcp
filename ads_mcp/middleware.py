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

"""Custom FastMCP middleware for handling request-scoped context."""

from __future__ import annotations

from collections.abc import Mapping
import logging
import os
from typing import Any, Mapping as MappingType, Optional, Set

from fastmcp.server.middleware import (
    CallNext,
    Middleware,
    MiddlewareContext,
)
from mcp.types import CallToolRequestParams

from ads_mcp import request_context

logger = logging.getLogger(__name__)

_AUTH_TOKEN_ENV_KEY = "auth_token"
_AUTH_TOKEN_ENV_VAR = "GOOGLE_ADS_MCP_AUTH_TOKEN"
_AUTH_TOKENS_ENV_VAR = "GOOGLE_ADS_MCP_AUTH_TOKENS"


def _load_allowed_tokens() -> Optional[Set[str]]:
    """Returns the configured set of allowed auth tokens, if any."""
    raw_tokens: list[str] = []

    multi = os.environ.get(_AUTH_TOKENS_ENV_VAR)
    if multi:
        raw_tokens.extend(token.strip() for token in multi.split(","))

    single = os.environ.get(_AUTH_TOKEN_ENV_VAR)
    if single:
        raw_tokens.append(single.strip())

    tokens = {token for token in raw_tokens if token}
    return tokens or None


def _extract_header_token(
    context: MiddlewareContext[CallToolRequestParams],
) -> Optional[str]:
    """Attempts to read a Bearer token from the Authorization header."""
    fastmcp_context = getattr(context, "fastmcp_context", None)
    if fastmcp_context is None:
        return None

    try:
        request = fastmcp_context.request_context.request
    except ValueError:
        return None

    if request is None:
        return None

    headers = getattr(request, "headers", None)
    if headers is None:
        return None

    auth_header = headers.get("Authorization")
    if not auth_header:
        return None

    scheme, _, value = auth_header.partition(" ")
    if scheme.lower() != "bearer":
        return None

    return value.strip() or None


def _authorize_token(token: Optional[str]) -> None:
    """Validates the provided token against the configured allow list."""
    allowed_tokens = _load_allowed_tokens()
    if not allowed_tokens:
        # No tokens configured; treat as open access (development mode).
        return

    if token is None:
        raise PermissionError("Unauthorized: missing auth token.")

    if token not in allowed_tokens:
        raise PermissionError("Unauthorized: invalid auth token.")


class RequestEnvironmentMiddleware(Middleware):
    """Stores per-request environment payloads in a context variable."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, Any],
    ) -> Any:
        raw_environment = getattr(context.message, "environment", None)

        sanitized_environment: MappingType[str, Any] | None = None
        token_from_environment: Optional[str] = None

        if isinstance(raw_environment, Mapping):
            mutable_environment = dict(raw_environment)
            raw_token = mutable_environment.pop(_AUTH_TOKEN_ENV_KEY, None)
            if isinstance(raw_token, str):
                token_from_environment = raw_token.strip() or None
            sanitized_environment = mutable_environment

            # Attempt to strip the token from the request payload so downstream
            # middleware cannot access it.
            try:
                context.message.environment = mutable_environment  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover - defensive
                logger.debug("Failed to sanitize environment payload", exc_info=True)

        token = token_from_environment or _extract_header_token(context)
        _authorize_token(token)

        with request_context.use_request_environment(sanitized_environment):
            return await call_next(context)
