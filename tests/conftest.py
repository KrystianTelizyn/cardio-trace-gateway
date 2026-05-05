import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import AppSettings, AuthSettings, InviteSettings, JwtSettings, RbacSettings, RouterSettings
from app.gateway.facade import Gateway
from app.main import create_app


def _test_app_settings() -> AppSettings:
    """
    Construct deterministic, in-memory AppSettings for tests.

    Values here are synthetic and only need to be structurally valid; individual tests
    should patch out any behaviour that would otherwise hit external services.
    """
    auth = AuthSettings(
        domain="example.auth0.com",
        audience="https://cardio-trace-api",
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="https://gateway.example.com/auth/callback",
        secret="test-secret",
        scope="openid profile",
        frontend_url="https://frontend.example.com",
    )
    invites = InviteSettings(
        auth0_domain="example.auth0.com",
        cardio_trace_clinic_id="clinic-123",
        patient_role_id="patient-role-id",
        doctor_role_id="doctor-role-id",
        api_explorer_client_id="mgmt-client-id",
        api_explorer_client_secret="mgmt-client-secret",
        auth0_client_id="app-client-id",
        cardio_trace_application_login_uri="https://cardio-trace-login/",
        invite_url_replacement="https://invite.example.com",
    )
    router = RouterSettings(
        inner_api_base_url="https://inner-api.example.com",
        hasura_graphql_url="https://graphql.example.com",
    )
    jwt = JwtSettings(
        domain="example.auth0.com",
        audience="https://cardio-trace-api",
        issuer="https://example.auth0.com/",
    )
    rbac = RbacSettings(enforcement_mode="enforce")
    return AppSettings(auth=auth, invites=invites, router=router, jwt=jwt, rbac=rbac)


@pytest.fixture
def example_access_token() -> str:
    """Placeholder token for tests; swap in a real sample when needed."""
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"


@pytest.fixture
def gateway() -> Gateway:
    settings = _test_app_settings()
    return Gateway(settings)


@pytest.fixture
def app(gateway: Gateway) -> FastAPI:
    app = create_app()
    app.state.gateway = gateway
    return app


@pytest.fixture
def client(app: FastAPI):
    with TestClient(app) as test_client:
        yield test_client
