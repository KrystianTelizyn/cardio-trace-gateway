import pytest

from app.config import AuthSettings
from app.gateway.auth_redirects import AuthRedirectPolicy


@pytest.fixture
def auth_redirect_policy() -> AuthRedirectPolicy:
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
    return AuthRedirectPolicy.from_auth_settings(settings)


@pytest.mark.parametrize(
    "input_return_to,expected",
    [
        (None, "/"),
        ("", "/"),
        ("/dashboard", "/dashboard"),
        ("/patients?tab=active", "/patients?tab=active"),
        ("dashboard", "/"),
        ("//evil.example.com", "/"),
        ("https://frontend.example.com/reports?year=2026", "/reports?year=2026"),
        ("https://evil.example.com/pwn", "/"),
    ],
)
def test_normalize_return_to_enforces_same_origin_or_relative_path(auth_redirect_policy, input_return_to, expected):
    assert auth_redirect_policy.normalize_return_to(input_return_to) == expected


def test_build_callback_success_redirect_url(auth_redirect_policy):
    url = auth_redirect_policy.build_callback_success_redirect_url("/patients?tab=active")
    assert url == "https://frontend.example.com/auth/callback/success?next=%2Fpatients%3Ftab%3Dactive"


def test_build_callback_error_redirect_url(auth_redirect_policy):
    url = auth_redirect_policy.build_callback_error_redirect_url("auth_callback_failed")
    assert url == "https://frontend.example.com/auth/callback/error?code=auth_callback_failed"


def test_frontend_secure_is_false_for_http_frontend(auth_redirect_policy):
    insecure_policy = AuthRedirectPolicy(
        frontend_url="http://localhost:3000",
        callback_success_path=auth_redirect_policy.callback_success_path,
        callback_error_path=auth_redirect_policy.callback_error_path,
    )
    assert insecure_policy.frontend_secure() is False

