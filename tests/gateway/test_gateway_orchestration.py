from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.config import AppSettings, AuthSettings, InviteSettings, JwtSettings, RouterSettings
from app.exceptions import AuthCallbackRedirectException
from app.schemas import InviteRole
from app.gateway.facade import Gateway


def _make_request(path: str = "/x", method: str = "GET", query: str = "") -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "query_string": query.encode(),
        "headers": [],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive=receive)


def _settings() -> AppSettings:
    return AppSettings(
        auth=AuthSettings(
            domain="tenant.auth0.com",
            audience="https://api.example.com",
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri="http://localhost/auth/callback",
            secret="auth-secret",
            scope="openid profile",
            frontend_url="https://frontend.example.com",
        ),
        invites=InviteSettings(
            auth0_domain="tenant.auth0.com",
            cardio_trace_clinic_id="org_1",
            patient_role_id="role_patient",
            doctor_role_id="role_doctor",
            api_explorer_client_id="id",
            api_explorer_client_secret="secret",
            auth0_client_id="auth0_client",
            cardio_trace_application_login_uri="https://login.example.com",
            invite_url_replacement="http://localhost:3000/login",
        ),
        router=RouterSettings(
            inner_api_base_url="https://inner.example.com",
            hasura_graphql_url="https://hasura.example.com/graphql",
        ),
        jwt=JwtSettings(
            domain="tenant.auth0.com",
            audience="https://api.example.com",
            issuer="https://tenant.auth0.com/",
        ),
    )


@pytest.fixture
def gateway(mocker):
    auth = mocker.Mock()
    jwt = mocker.Mock()
    invites = mocker.Mock()
    router = mocker.Mock()
    mocker.patch("app.gateway.facade.GatewayAuth", return_value=auth)
    mocker.patch("app.gateway.facade.GatewayJwt", return_value=jwt)
    mocker.patch("app.gateway.facade.Invites", return_value=invites)
    mocker.patch("app.gateway.facade.GatewayRouter", return_value=router)
    gw = Gateway(_settings())
    return gw, auth, jwt, invites, router


@pytest.mark.asyncio
async def test_get_me_aggregates_claims_from_jwt_and_session(gateway):
    gw, auth, jwt, _, _ = gateway
    jwt.validate_access_token.return_value = {
        "sub": "u1",
        "org_id": "org1",
        "scope": "openid profile",
        "permissions": ["read:patients"],
        "https://cardio-trace.com/roles": ["doctor"],
    }
    auth.get_session_from_request = AsyncMock(
        return_value={"user": {"email": "a@b.com", "name": "Name"}}
    )
    auth.get_identity_claims_from_session.return_value = {
        "email": "a@b.com",
        "name": "Name",
        "picture": None,
    }

    payload = await gw.get_me(_make_request(), Response(), "token")
    assert payload["sub"] == "u1"
    assert payload["roles"] == ["doctor"]
    assert payload["email"] == "a@b.com"


@pytest.mark.asyncio
async def test_complete_callback_sets_csrf_cookie(gateway):
    gw, auth, _, _, _ = gateway
    auth.process_callback = AsyncMock(
        return_value={"success": True, "return_to": "/dashboard", "flow_type": "login"}
    )
    request = _make_request(path="/auth/callback", query="code=1&state=2")
    response = Response()
    callback_result = await gw.complete_callback(request, response)
    assert callback_result == {"return_to": "/dashboard", "flow_type": "login"}
    auth.process_callback.assert_called_once()
    auth.set_csrf_token_cookie.assert_called_once_with(response)


@pytest.mark.asyncio
async def test_callback_redirect_response_success(gateway):
    gw, auth, _, _, _ = gateway
    auth.process_callback = AsyncMock(
        return_value={"success": True, "return_to": "/patients", "flow_type": "login"}
    )
    auth.success_redirect_url.side_effect = [
        "https://frontend.example.com/auth/callback/success?next=%2F",
        "https://frontend.example.com/auth/callback/success?next=%2Fpatients",
    ]
    request = _make_request(path="/auth/callback", query="code=1&state=2")

    response = await gw.callback_redirect_response(request)

    assert response.status_code == 302
    assert response.headers["location"] == (
        "https://frontend.example.com/auth/callback/success?next=%2Fpatients"
    )


@pytest.mark.asyncio
async def test_callback_redirect_response_error_raises_dedicated_exception(gateway):
    gw, auth, _, _, _ = gateway
    auth.process_callback = AsyncMock(side_effect=AuthCallbackRedirectException())
    auth.success_redirect_url.return_value = (
        "https://frontend.example.com/auth/callback/success?next=%2F"
    )
    request = _make_request(path="/auth/callback", query="error=access_denied&state=2")

    with pytest.raises(AuthCallbackRedirectException):
        await gw.callback_redirect_response(request)


@pytest.mark.parametrize("return_to", [None, "/home"])
@pytest.mark.asyncio
async def test_logout_user_clears_csrf_cookie(gateway, return_to):
    gw, auth, _, _, _ = gateway
    auth.process_logout = AsyncMock(return_value="https://auth.example.com/logout")
    response = Response()
    logout_url = await gw.logout_user(_make_request(), response, return_to=return_to)
    assert logout_url == "https://auth.example.com/logout"
    auth.process_logout.assert_called_once()
    call_kwargs = auth.process_logout.call_args.kwargs
    assert call_kwargs["return_to"] == return_to
    auth.clear_csrf_token_cookie.assert_called_once_with(response)


def test_create_invite_dispatches_by_role(gateway):
    gw, _, _, invites, _ = gateway
    invites.invite_patient.return_value = "patient-url"
    invites.invite_doctor.return_value = "doctor-url"
    assert gw.create_invite("p@example.com", InviteRole.patient) == "patient-url"
    assert gw.create_invite("d@example.com", InviteRole.doctor) == "doctor-url"


@pytest.mark.asyncio
async def test_proxy_methods_build_trust_context_and_forward(gateway):
    gw, _, jwt_mock, _, router = gateway
    ctx_a = SimpleNamespace(user_id="u1", tenant_id="org1", role="doctor")
    ctx_b = SimpleNamespace(user_id="u2", tenant_id="org2", role="patient")
    jwt_mock.build_trust_context.side_effect = [ctx_a, ctx_b]
    router.api = AsyncMock(return_value=SimpleNamespace(status_code=200))
    router.graphql = AsyncMock(return_value=SimpleNamespace(status_code=200))
    request = _make_request(path="/api/patients")

    await gw.proxy_api(request, "patients", "token-a")
    await gw.proxy_graphql(_make_request(path="/graphql"), "token-b")

    jwt_mock.build_trust_context.assert_any_call("token-a")
    jwt_mock.build_trust_context.assert_any_call("token-b")
    router.api.assert_called_once_with(request, "patients", ctx_a)
    router.graphql.assert_called_once()
    assert router.graphql.call_args.args[1] == ctx_b

@pytest.mark.asyncio
async def test_notifies_invite_registration_completed(gateway):
    gw, auth, _, _, _ = gateway
    auth.INVITE_ACCEPT_FLOW = "invite_accept"
    gw._notify_invite_registration_completed = Mock()
    gw.complete_callback = AsyncMock(
        return_value={"success": True, "return_to": "/dashboard", "flow_type": "invite_accept"}
    )
    request = _make_request(path="/auth/callback", query="code=1&state=2")
    response = await gw.callback_redirect_response(request)
    gw._notify_invite_registration_completed.assert_called_once()