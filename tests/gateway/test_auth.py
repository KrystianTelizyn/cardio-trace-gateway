import pytest

from app.exceptions import AuthServiceException, CsrfValidationError
from app.gateway.auth import GatewayAuth
from auth0_server_python.error import Auth0Error
from starlette.requests import Request
from starlette.responses import Response


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


@pytest.fixture
def auth_service(mocker):
    mock_server_client = mocker.patch("app.gateway.auth.ServerClient", autospec=True)
    service = GatewayAuth()
    return service, mock_server_client.return_value


@pytest.mark.asyncio
async def test_get_access_token_from_session(auth_service):
    service, server_client = auth_service
    server_client.get_access_token.return_value = "token-123"
    request = _make_request("GET")
    token = await service.get_access_token_from_session(request, Response())
    assert token == "token-123"


@pytest.mark.asyncio
async def test_build_login_url_maps_auth0_error(auth_service):
    service, server_client = auth_service
    server_client.start_interactive_login.side_effect = Auth0Error("boom")
    with pytest.raises(AuthServiceException):
        await service.build_login_url(store_options={})


def test_set_and_clear_csrf_cookie(auth_service):
    service, _ = auth_service
    response = Response()
    token = service.set_csrf_token_cookie(response)
    assert token
    assert "gateway_csrf=" in response.headers.get("set-cookie", "")

    clear_response = Response()
    service.clear_csrf_token_cookie(clear_response)
    assert "gateway_csrf=" in clear_response.headers.get("set-cookie", "")


def test_validate_csrf_token_passes_when_tokens_match(auth_service):
    service, _ = auth_service
    request = _make_request(
        "POST",
        headers={"X-CSRF-Token": "token-a"},
        cookie="gateway_csrf=token-a",
    )
    service.validate_csrf_token(request, {"POST"})


def test_validate_csrf_token_raises_on_mismatch(auth_service):
    service, _ = auth_service
    request = _make_request(
        "POST",
        headers={"X-CSRF-Token": "token-a"},
        cookie="gateway_csrf=token-b",
    )
    with pytest.raises(CsrfValidationError):
        service.validate_csrf_token(request, {"POST"})
