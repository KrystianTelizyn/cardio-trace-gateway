from typing import Any

import httpx
from starlette.requests import Request
from starlette.responses import Response

from app.config import RouterSettings
from app.gateway.jwt import TrustContext

_RESPONSE_DROP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

_REQUEST_FORWARD_ALLOWLIST = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "content-type",
        "user-agent",
        "x-request-id",
    }
)


def _merge_query_into_url(base_url: str, query: str) -> str:
    if not query:
        return base_url
    connector = "&" if "?" in base_url else "?"
    return f"{base_url}{connector}{query}"


def _forwarded_request_headers(request: Request) -> dict[str, str]:
    return {
        name: value
        for name, value in request.headers.items()
        if name.lower() in _REQUEST_FORWARD_ALLOWLIST
    }


class GatewayRouter:
    def __init__(self, settings: RouterSettings) -> None:
        self._settings = settings
        self._inner_api_base = settings.inner_api_base_url.rstrip("/")
        self._hasura_graphql_url = settings.hasura_graphql_url.rstrip("/")
        self._http = httpx.AsyncClient()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def request_internal(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Make a gateway-initiated request to an upstream internal service."""
        url = f"{self._inner_api_base}{path}"
        return await self._http.request(method, url, json=json, headers=headers)

    def _build_api_headers(self, request: Request, ctx: TrustContext) -> dict[str, str]:
        api_headers = {
            "X-User-Id": ctx.user_id,
            "X-Tenant-Id": ctx.tenant_id,
            "X-Role": ctx.role,
        }  
        api_headers.update(_forwarded_request_headers(request))
        return api_headers

    def _build_graphql_headers(self, request: Request, ctx: TrustContext) -> dict[str, str]:
        graphql_headers = {
            "X-Hasura-User-Id": ctx.user_id,
            "X-Hasura-Org-Id": ctx.tenant_id,
            "X-Hasura-Role": ctx.role,
        }
        graphql_headers.update(_forwarded_request_headers(request))
        return graphql_headers

    def _upstream_response(self, upstream: httpx.Response) -> Response:
        headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in _RESPONSE_DROP
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=headers,
        )

    async def api(self, request: Request, proxy_path: str, ctx: TrustContext) -> Response:
        #path = "/api/" if not proxy_path else f"/api/{proxy_path}"
        path = proxy_path
        query = request.url.query
        url = f"{self._inner_api_base}{path}"
        # TBD: Additional routing logic here, e.g. to handle different paths over different services.
        # for now, we just proxy all requests to the inner API base URL.
        url = _merge_query_into_url(url, query)
        body = await request.body()
        headers = self._build_api_headers(request, ctx)
        upstream = await self._http.request(
            request.method,
            url,
            headers=headers,
            content=body,
        )
        return self._upstream_response(upstream)

    async def graphql(self, request: Request, ctx: TrustContext) -> Response:
        query = request.url.query
        url = _merge_query_into_url(self._hasura_graphql_url, query)
        body = await request.body()
        headers = self._build_graphql_headers(request, ctx)
        upstream = await self._http.request(
            request.method,
            url,
            headers=headers,
            content=body,
        )
        return self._upstream_response(upstream)
