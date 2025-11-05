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
from typing import Any

from fastmcp.server.middleware import (
    CallNext,
    Middleware,
    MiddlewareContext,
)
from mcp.types import CallToolRequestParams

from ads_mcp import request_context


class RequestEnvironmentMiddleware(Middleware):
    """Stores per-request environment payloads in a context variable."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, Any],
    ) -> Any:
        environment = getattr(context.message, "environment", None)

        # Pydantic BaseModel extras can be any object; only pass mappings.
        if not isinstance(environment, Mapping):
            environment = None

        with request_context.use_request_environment(environment):
            return await call_next(context)
