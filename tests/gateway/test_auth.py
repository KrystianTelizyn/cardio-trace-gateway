import pytest
from http.cookies import SimpleCookie
import re

from app.config import AuthSettings
from app.exceptions import AuthCallbackRedirectException, AuthServiceException, CsrfValidationError
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
    settings = AuthSettings(
        domain="tenant.auth0.com",
        audience="https://api.example.com",
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="http://localhost/callback",
        secret="auth0-secret",
        scope="openid profile",
        frontend_url="https://frontend.example.com",
    )
    service = GatewayAuth(settings)
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


@pytest.mark.asyncio
async def test_build_login_url_passes_base_authorization_params(auth_service):
    service, server_client = auth_service
    server_client.start_interactive_login.return_value = "https://tenant.auth0.com/authorize"
    store_options = {"request": object(), "response": object()}

    url = await service.build_login_url(store_options=store_options)

    assert url == "https://tenant.auth0.com/authorize"
    server_client.start_interactive_login.assert_called_once()
    _, kwargs = server_client.start_interactive_login.call_args
    assert kwargs["store_options"] is store_options

    auth_params = kwargs["options"].authorization_params
    assert auth_params == {
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile",
        "audience": "https://api.example.com",
    }
    assert kwargs["options"].app_state == {"return_to": "/", "flow_type": "login"}


@pytest.mark.asyncio
async def test_build_invite_login_url_passes_invitation_authorization_params(auth_service):
    service, server_client = auth_service
    server_client.start_interactive_login.return_value = "https://tenant.auth0.com/authorize"

    await service.build_invite_login_url(
        store_options={},
        invitation="inv_123",
        organization="org_456",
        organization_name="Cardio Trace Org",
    )

    _, kwargs = server_client.start_interactive_login.call_args
    auth_params = kwargs["options"].authorization_params
    assert auth_params["invitation"] == "inv_123"
    assert auth_params["organization"] == "org_456"
    assert auth_params["organization_name"] == "Cardio Trace Org"


@pytest.mark.asyncio
async def test_build_login_url_normalizes_return_to_into_app_state(auth_service):
    service, server_client = auth_service
    server_client.start_interactive_login.return_value = "https://tenant.auth0.com/authorize"

    await service.build_login_url(
        store_options={},
        return_to="https://frontend.example.com/patients?tab=active",
    )

    _, kwargs = server_client.start_interactive_login.call_args
    assert kwargs["options"].app_state == {
        "return_to": "/patients?tab=active",
        "flow_type": "login",
    }


@pytest.mark.asyncio
async def test_build_invite_login_url_sets_invite_flow_type_in_app_state(auth_service):
    service, server_client = auth_service
    server_client.start_interactive_login.return_value = "https://tenant.auth0.com/authorize"

    await service.build_invite_login_url(
        store_options={},
        invitation="inv_123",
        organization="org_456",
        organization_name="Cardio Trace Org",
    )

    _, kwargs = server_client.start_interactive_login.call_args
    assert kwargs["options"].app_state == {"return_to": "/", "flow_type": "invite_accept"}


@pytest.mark.asyncio
async def test_process_callback_passes_url_exactly_to_server_client(auth_service):
    service, server_client = auth_service
    callback_url = (
        "http://localhost/callback?code=abc123&state=xyz789"
        "&returnTo=%2Fdashboard%3Ftab%3Dprofile"
    )
    store_options = {"request": object(), "response": object()}
    server_client.complete_interactive_login.return_value = {
        "state_data": {"ok": True},
        "app_state": {"return_to": "/dashboard?tab=profile"},
    }

    result = await service.process_callback(callback_url, store_options)

    assert result == {"success": True, "return_to": "/dashboard?tab=profile", "flow_type": "login"}
    server_client.complete_interactive_login.assert_called_once_with(
        url=callback_url,
        store_options=store_options,
    )


@pytest.mark.asyncio
async def test_process_callback_maps_auth0_error(auth_service):
    service, server_client = auth_service
    server_client.complete_interactive_login.side_effect = Auth0Error("boom")

    with pytest.raises(AuthCallbackRedirectException):
        await service.process_callback("http://localhost/callback?code=bad", store_options={})


def test_set_and_clear_csrf_cookie(auth_service):
    service, _ = auth_service
    response = Response()
    token = service.set_csrf_token_cookie(response)
    set_cookie_header = response.headers.get("set-cookie", "")
    assert re.match(r'^[a-zA-Z0-9-_]+$', token)
    assert f"gateway_csrf={token}" in set_cookie_header
    assert "Path=/" in set_cookie_header
    assert "SameSite=lax" in set_cookie_header
    assert "HttpOnly" not in set_cookie_header
    assert "Secure" in set_cookie_header

    clear_response = Response()
    service.clear_csrf_token_cookie(clear_response)
    clear_cookie_header = clear_response.headers.get("set-cookie", "")
    assert "gateway_csrf=\"\"" in clear_cookie_header
    assert "Path=/" in clear_cookie_header
    assert "Max-Age=0" in clear_cookie_header
    assert "expires=" in clear_cookie_header.lower()

    clear_cookie = SimpleCookie()
    clear_cookie.load(clear_cookie_header)
    assert clear_cookie["gateway_csrf"].value == ""


def test_set_csrf_cookie_not_secure_for_http_frontend(mocker):
    mocker.patch("app.gateway.auth.ServerClient", autospec=True)
    settings = AuthSettings(
        domain="tenant.auth0.com",
        audience="https://api.example.com",
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="http://localhost/callback",
        secret="auth0-secret",
        scope="openid profile",
        frontend_url="http://localhost:3000",
    )
    service = GatewayAuth(settings)
    response = Response()

    service.set_csrf_token_cookie(response)
    set_cookie_header = response.headers.get("set-cookie", "")
    assert "gateway_csrf=" in set_cookie_header
    assert "Secure" not in set_cookie_header


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


@pytest.mark.parametrize(
    "headers,cookie",
    [
        ({}, "gateway_csrf=token-a"),
        ({"X-CSRF-Token": "token-a"}, None),
        ({}, None),
    ],
)
def test_validate_csrf_token_raises_when_token_missing_for_protected_method(
    auth_service, headers, cookie
):
    service, _ = auth_service
    request = _make_request("POST", headers=headers, cookie=cookie)

    with pytest.raises(CsrfValidationError):
        service.validate_csrf_token(request, {"POST"})
