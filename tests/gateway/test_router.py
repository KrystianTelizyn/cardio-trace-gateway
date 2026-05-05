import pytest
from starlette.requests import Request

from app.config import RouterSettings
from app.gateway.jwt import TrustContext
from app.gateway.router import GatewayRouter, _merge_query_into_url, _normalize_proxy_path

_TEST_CTX = TrustContext(user_id="auth0|abc123", tenant_id="org_42", role="doctor")


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


@pytest.fixture
def gateway_router() -> GatewayRouter:
    return GatewayRouter(
        RouterSettings(
            inner_api_base_url="https://inner.example.com",
            hasura_graphql_url="https://hasura.example.com/graphql",
        )
    )


def test_merge_query_into_url():
    assert _merge_query_into_url("https://api.example.com/items", "a=1") == "https://api.example.com/items?a=1"
    assert _merge_query_into_url("https://api.example.com/items?x=1", "a=1") == "https://api.example.com/items?x=1&a=1"
    assert _merge_query_into_url("https://api.example.com/items", "") == "https://api.example.com/items"


@pytest.mark.parametrize(
    "proxy_path,expected",
    [
        ("users", "/users"),
        ("/users", "/users"),
        ("", "/"),
    ],
)
def test_normalize_proxy_path(proxy_path: str, expected: str):
    assert _normalize_proxy_path(proxy_path) == expected


def test_build_api_headers_injects_trust_context(gateway_router: GatewayRouter):
    request = _make_request(
        "GET",
        "/api/users",
        headers={
            "Accept": "application/json",
            "User-Agent": "pytest",
            "X-Internal": "drop-me",
        },
    )
    headers = gateway_router._build_api_headers(request, _TEST_CTX)

    assert headers["X-User-Id"] == "auth0|abc123"
    assert headers["X-Tenant-Id"] == "org_42"
    assert headers["X-Role"] == "doctor"
    assert headers["accept"] == "application/json"
    assert "Authorization" not in headers
    assert "x-internal" not in headers


def test_build_api_headers_forwards_allowlisted_case_insensitive(gateway_router: GatewayRouter):
    request = _make_request(
        "GET",
        "/api/users",
        headers={
            "ACCEPT-LANGUAGE": "en-US",
            "X-REQUEST-ID": "req-123",
            "Cookie": "a=1",
            "Authorization": "Bearer token",
        },
    )
    headers = gateway_router._build_api_headers(request, _TEST_CTX)
    assert headers["accept-language"] == "en-US"
    assert headers["x-request-id"] == "req-123"
    assert "cookie" not in headers
    assert "authorization" not in headers


def test_build_graphql_headers_injects_hasura_session_variables(gateway_router: GatewayRouter):
    request = _make_request(
        "POST",
        "/graphql",
        headers={"Content-Type": "application/json"},
    )
    headers = gateway_router._build_graphql_headers(request, _TEST_CTX)

    assert headers["X-Hasura-User-Id"] == "auth0|abc123"
    assert headers["X-Hasura-Org-Id"] == "org_42"
    assert headers["X-Hasura-Role"] == "doctor"
    assert headers["content-type"] == "application/json"
    assert "Authorization" not in headers


@pytest.mark.asyncio
async def test_api_forwards_request_and_filters_response_headers(mocker, gateway_router: GatewayRouter):
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
    request_mock = mocker.patch.object(gateway_router._http, "request", return_value=upstream)

    response = await gateway_router.api(request, "users", _TEST_CTX)
    assert response.status_code == 201
    assert response.headers.get("transfer-encoding") is None
    assert response.body == b'{"ok":true}'
    request_mock.assert_called_once()
    assert request_mock.call_args.args[0] == "POST"
    assert request_mock.call_args.args[1] == "https://inner.example.com/users?active=true"
    assert request_mock.call_args.kwargs["content"] == b'{"x":1}'
    sent_headers = request_mock.call_args.kwargs["headers"]
    assert sent_headers["X-User-Id"] == "auth0|abc123"
    assert "Authorization" not in sent_headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "proxy_path,expected_url",
    [
        ("users", "https://inner.example.com/users"),
        ("/users", "https://inner.example.com/users"),
        ("some/path", "https://inner.example.com/some/path"),
    ],
)
async def test_api_forwards_proxy_path_as_provided(
    mocker, gateway_router: GatewayRouter, proxy_path: str, expected_url: str
):
    request = _make_request("GET", "/api/users")
    upstream = mocker.Mock(content=b"{}", status_code=200, headers={"content-type": "application/json"})
    request_mock = mocker.patch.object(gateway_router._http, "request", return_value=upstream)

    await gateway_router.api(request, proxy_path, _TEST_CTX)

    assert request_mock.call_args.args[1] == expected_url


@pytest.mark.asyncio
async def test_request_internal_forwards_method_path_body_and_headers(mocker, gateway_router: GatewayRouter):
    upstream = mocker.Mock()
    request_mock = mocker.patch.object(gateway_router._http, "request", return_value=upstream)
    payload = {"user_id": "auth0|123", "email": "user@example.com"}
    headers = {"X-Request-Id": "req-1"}

    response = await gateway_router.request_internal(
        "POST",
        "/users",
        json=payload,
        headers=headers,
    )

    assert response is upstream
    request_mock.assert_called_once_with(
        "POST",
        "https://inner.example.com/users",
        json=payload,
        headers=headers,
    )


@pytest.mark.asyncio
async def test_graphql_forwards_query_string(mocker, gateway_router: GatewayRouter):
    request = _make_request("GET", "/graphql", query="query=%7Bviewer%7Bid%7D%7D")
    upstream = mocker.Mock(content=b'{"data":{"viewer":{"id":"1"}}}', status_code=200, headers={"content-type": "application/json"})
    request_mock = mocker.patch.object(gateway_router._http, "request", return_value=upstream)

    await gateway_router.graphql(request, _TEST_CTX)

    assert request_mock.call_args.args[1] == "https://hasura.example.com/graphql?query=%7Bviewer%7Bid%7D%7D"


@pytest.mark.asyncio
async def test_api_filters_connection_related_response_headers(mocker, gateway_router: GatewayRouter):
    request = _make_request("GET", "/api/users")
    upstream = mocker.Mock()
    upstream.content = b'{"ok":true}'
    upstream.status_code = 200
    upstream.headers = {
        "content-type": "application/json",
        "connection": "close",
        "keep-alive": "timeout=5",
        "upgrade": "h2c",
        "transfer-encoding": "chunked",
    }
    mocker.patch.object(gateway_router._http, "request", return_value=upstream)

    response = await gateway_router.api(request, "/users", _TEST_CTX)

    assert response.headers.get("connection") is None
    assert response.headers.get("keep-alive") is None
    assert response.headers.get("upgrade") is None
    assert response.headers.get("transfer-encoding") is None
    assert response.headers.get("content-type") == "application/json"


@pytest.mark.asyncio
async def test_graphql_forwards_to_hasura(mocker, gateway_router: GatewayRouter):
    request = _make_request("POST", "/graphql", body=b'{"query":"{x}"}')
    upstream = mocker.Mock()
    upstream.content = b'{"data":{"x":1}}'
    upstream.status_code = 200
    upstream.headers = {"content-type": "application/json"}
    request_mock = mocker.patch.object(gateway_router._http, "request", return_value=upstream)

    response = await gateway_router.graphql(request, _TEST_CTX)
    assert response.status_code == 200
    assert response.body == b'{"data":{"x":1}}'
    request_mock.assert_called_once()
    called_url = request_mock.call_args.args[1]
    assert called_url == "https://hasura.example.com/graphql"
    assert request_mock.call_args.kwargs["content"] == b'{"query":"{x}"}'
    sent_headers = request_mock.call_args.kwargs["headers"]
    assert sent_headers["X-Hasura-User-Id"] == "auth0|abc123"
    assert sent_headers["X-Hasura-Role"] == "doctor"
    assert "Authorization" not in sent_headers
