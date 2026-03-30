import httpx
from starlette.requests import Request
from starlette.responses import Response

# Hop-by-hop and other headers we do not forward back to the client
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


class GatewayRouter:
    def __init__(self, inner_api_base: str, hasura_graphql_url: str) -> None:
        self._inner_api_base = inner_api_base.rstrip("/")
        self._hasura_graphql_url = hasura_graphql_url.rstrip("/")
        self._http = httpx.AsyncClient()

    async def aclose(self) -> None:
        await self._http.aclose()

    def _build_upstream_headers(self, request: Request, access_token: str) -> dict[str, str]:
        out: dict[str, str] = {"Authorization": f"Bearer {access_token}"}
        for name, value in request.headers.items():
            if name.lower() in _REQUEST_FORWARD_ALLOWLIST:
                out[name] = value
        return out

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

    async def api(self, request: Request, proxy_path: str, access_token: str) -> Response:
        path = "/api/" if not proxy_path else f"/api/{proxy_path}"
        query = request.url.query
        url = f"{self._inner_api_base}{path}"
        url = _merge_query_into_url(url, query)
        body = await request.body()
        headers = self._build_upstream_headers(request, access_token)
        upstream = await self._http.request(
            request.method,
            url,
            headers=headers,
            content=body,
        )
        return self._upstream_response(upstream)

    async def graphql(self, request: Request, access_token: str) -> Response:
        query = request.url.query
        url = _merge_query_into_url(self._hasura_graphql_url, query)
        body = await request.body()
        headers = self._build_upstream_headers(request, access_token)
        upstream = await self._http.request(
            request.method,
            url,
            headers=headers,
            content=body,
        )
        return self._upstream_response(upstream)
