from starlette.requests import Request

from app.config import RouterSettings
from app.gateway.router import GatewayRouter, _merge_query_into_url


def _make_request(method: str, path: str, query: str = "", headers: dict[str, str] | None = None, body: bytes = b"") -> Request:
    raw_headers = []
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode(), v.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "query_string": query.encode(),
        "headers": raw_headers,
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive=receive)


def test_merge_query_into_url():
    assert _merge_query_into_url("https://api.example.com/items", "a=1") == "https://api.example.com/items?a=1"
    assert _merge_query_into_url("https://api.example.com/items?x=1", "a=1") == "https://api.example.com/items?x=1&a=1"


def test_build_upstream_headers_allowlist():
    settings = RouterSettings(
        inner_api_base_url="https://inner.example.com",
        hasura_graphql_url="https://hasura.example.com/graphql",
    )
    router = GatewayRouter(settings)
    request = _make_request(
        "GET",
        "/api/users",
        headers={
            "Accept": "application/json",
            "User-Agent": "pytest",
            "X-Internal": "drop-me",
        },
    )
    headers = router._build_upstream_headers(request, "token-1")
    assert headers["Authorization"] == "Bearer token-1"
    assert headers["accept"] == "application/json"
    assert "x-internal" not in headers


async def test_api_forwards_request_and_filters_response_headers(mocker):
    settings = RouterSettings(
        inner_api_base_url="https://inner.example.com",
        hasura_graphql_url="https://hasura.example.com/graphql",
    )
    router = GatewayRouter(settings)
    request = _make_request(
        "POST",
        "/api/users",
        query="active=true",
        headers={"Content-Type": "application/json", "X-Request-Id": "abc123"},
        body=b'{"x":1}',
    )
    upstream = mocker.Mock()
    upstream.content = b'{"ok":true}'
    upstream.status_code = 201
    upstream.headers = {"content-type": "application/json", "transfer-encoding": "chunked"}
    request_mock = mocker.patch.object(router._http, "request", return_value=upstream)

    response = await router.api(request, "users", "token-2")
    assert response.status_code == 201
    assert response.headers.get("transfer-encoding") is None
    assert response.body == b'{"ok":true}'
    request_mock.assert_called_once()
    assert request_mock.call_args.args[0] == "POST"
    assert request_mock.call_args.args[1] == "https://inner.example.com/api/users?active=true"
    assert request_mock.call_args.kwargs["content"] == b'{"x":1}'


async def test_graphql_forwards_to_hasura(mocker):
    settings = RouterSettings(
        inner_api_base_url="https://inner.example.com",
        hasura_graphql_url="https://hasura.example.com/graphql",
    )
    router = GatewayRouter(settings)
    request = _make_request("POST", "/graphql", body=b'{"query":"{x}"}')
    upstream = mocker.Mock()
    upstream.content = b'{"data":{"x":1}}'
    upstream.status_code = 200
    upstream.headers = {"content-type": "application/json"}
    request_mock = mocker.patch.object(router._http, "request", return_value=upstream)

    response = await router.graphql(request, "token-3")
    assert response.status_code == 200
    assert response.body == b'{"data":{"x":1}}'
    request_mock.assert_called_once()
    called_url = request_mock.call_args.args[1]
    assert called_url == "https://hasura.example.com/graphql"
    assert request_mock.call_args.kwargs["content"] == b'{"query":"{x}"}'
