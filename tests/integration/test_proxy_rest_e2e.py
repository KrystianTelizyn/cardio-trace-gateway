import pytest

# The integration user is a doctor (asserted in test_playwright_auth_e2e).


@pytest.mark.integration
def test_rest_proxy_reaches_backend_for_allowed_role(integration_client, auth_session):
    """doctor may PATCH /api/me/profile: the gateway forwards it and the backend answers."""
    response = integration_client.patch(
        "/api/me/profile",
        headers=auth_session.headers(),
        json={},
    )
    # 401/403 would mean the edge (session, CSRF, RBAC) or the trust contract rejected it.
    assert response.status_code not in (401, 403, 404, 405), response.text
    assert response.status_code < 500, response.text


@pytest.mark.integration
def test_rest_proxy_denies_role_at_the_edge(integration_client, auth_session):
    """measurement sessions are patient-only: a doctor is stopped by edge RBAC."""
    response = integration_client.post(
        "/api/measurement-sessions",
        headers=auth_session.headers(),
        json={},
    )
    assert response.status_code == 403, response.text
    assert response.json() == {
        "detail": "Forbidden",
        "code": "rbac_denied",
        "path": "/api/measurement-sessions",
        "method": "POST",
    }


@pytest.mark.integration
def test_rest_proxy_has_no_catch_all(integration_client, auth_session):
    """Only declared routes are proxied; anything else never reaches the backend."""
    response = integration_client.get("/api/health", headers=auth_session.headers())
    assert response.status_code == 404, response.text
