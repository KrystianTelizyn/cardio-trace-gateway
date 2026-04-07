import pytest


@pytest.mark.integration
def test_auth0_login_url_endpoint_returns_auth0_redirect(integration_client, integration_env):
    response = integration_client.get("/url/auth0")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "login_url" in payload
    assert integration_env["INTEGRATION_AUTH0_DOMAIN"] in payload["login_url"]


@pytest.mark.integration
def test_callback_sets_gateway_csrf_cookie_when_query_provided(
    integration_client, callback_query_string
):
    if not callback_query_string:
        pytest.skip("Set INTEGRATION_AUTH0_CALLBACK_QUERY to run callback integration test.")

    response = integration_client.get(f"/callback?{callback_query_string}")
    assert response.status_code == 302, response.text
    assert "/auth/callback/success" in response.headers.get("location", "")
    set_cookie = response.headers.get("set-cookie", "")
    assert "gateway_csrf=" in set_cookie


@pytest.mark.integration
def test_healthz_liveness(integration_client):
    response = integration_client.get("/healthz")
    assert response.status_code == 200, response.text
    assert response.json().get("status") == "ok"


@pytest.mark.integration
def test_readyz_readiness(integration_client):
    response = integration_client.get("/readyz")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload.get("status") == "ok"
    assert isinstance(payload.get("checks"), dict)


@pytest.mark.integration
def test_me_with_real_session_cookie(integration_client, integration_session_cookie):
    if not integration_session_cookie:
        pytest.skip("Set INTEGRATION_SESSION_COOKIE to run authenticated /me test.")

    response = integration_client.get(
        "/me",
        headers={"Cookie": integration_session_cookie},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    for key in ("sub", "org_id", "scope", "permissions", "roles", "email", "name", "picture"):
        assert key in payload


@pytest.mark.integration
def test_me_unauthenticated_returns_401(integration_client):
    response = integration_client.get("/me")
    assert response.status_code == 401
