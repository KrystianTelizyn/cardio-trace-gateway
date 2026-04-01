from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.config import AppSettings, AuthSettings, InviteSettings, JwtSettings, RouterSettings
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
            redirect_uri="http://localhost/callback",
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
            inner_auth_service_url="https://inner.example.com",
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
    auth.process_callback = AsyncMock(return_value={"success": True})
    request = _make_request(path="/callback", query="code=1&state=2")
    response = Response()
    await gw.complete_callback(request, response)
    auth.process_callback.assert_called_once()
    auth.set_csrf_token_cookie.assert_called_once_with(response)


@pytest.mark.asyncio
async def test_logout_user_clears_csrf_cookie(gateway):
    gw, auth, _, _, _ = gateway
    auth.process_logout = AsyncMock(return_value="https://auth.example.com/logout")
    response = Response()
    logout_url = await gw.logout_user(_make_request(), response)
    assert logout_url == "https://auth.example.com/logout"
    auth.clear_csrf_token_cookie.assert_called_once_with(response)


def test_create_invite_dispatches_by_role(gateway):
    gw, _, _, invites, _ = gateway
    invites.invite_patient.return_value = "patient-url"
    invites.invite_doctor.return_value = "doctor-url"
    assert gw.create_invite("p@example.com", InviteRole.patient) == "patient-url"
    assert gw.create_invite("d@example.com", InviteRole.doctor) == "doctor-url"


@pytest.mark.asyncio
async def test_proxy_methods_validate_and_forward(gateway):
    gw, _, jwt, _, router = gateway
    router.api = AsyncMock(return_value=SimpleNamespace(status_code=200))
    router.graphql = AsyncMock(return_value=SimpleNamespace(status_code=200))
    request = _make_request(path="/api/patients")

    await gw.proxy_api(request, "patients", "token-a")
    await gw.proxy_graphql(_make_request(path="/graphql"), "token-b")

    jwt.validate_access_token.assert_any_call("token-a")
    jwt.validate_access_token.assert_any_call("token-b")
    router.api.assert_called_once_with(request, "patients", "token-a")
    router.graphql.assert_called_once()
