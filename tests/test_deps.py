import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from app.deps import csrf_api, csrf_graphql, require_cookie_access_token
from auth0_server_python.error import AccessTokenError


def _make_request(method: str, headers: dict[str, str] | None = None, cookie: str | None = None) -> Request:
    raw_headers = []
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode(), v.encode()))
    if cookie:
        raw_headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": "/api/resource",
        "query_string": b"",
        "headers": raw_headers,
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive=receive)


@pytest.mark.asyncio
async def test_require_cookie_access_token_success(gateway):
    request = _make_request("GET")
    response = Response()
    token = await require_cookie_access_token(request, response, gateway)
    assert token == "example-access-token"


@pytest.mark.asyncio
async def test_require_cookie_access_token_unauthenticated(gateway, mocker):
    request = _make_request("GET")
    response = Response()
    mocker.patch.object(
        gateway.auth,
        "get_access_token_from_session",
        side_effect=AccessTokenError("missing_token", "missing"),
    )
    with pytest.raises(HTTPException) as exc:
        await require_cookie_access_token(request, response, gateway)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Not authenticated"


def test_csrf_api_skips_safe_methods(gateway):
    request = _make_request("GET")
    csrf_api(request, gateway)


def test_csrf_api_requires_matching_token(gateway):
    request = _make_request(
        "POST",
        headers={"X-CSRF-Token": "token-1"},
        cookie="gateway_csrf=token-1",
    )
    csrf_api(request, gateway)


def test_csrf_graphql_requires_matching_token(gateway):
    request = _make_request(
        "POST",
        headers={"X-CSRF-Token": "token-2"},
        cookie="gateway_csrf=token-2",
    )
    csrf_graphql(request, gateway)
