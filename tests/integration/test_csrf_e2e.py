import pytest


@pytest.mark.integration
def test_rest_mutation_without_csrf_header_is_rejected(integration_client, auth_session):
    response = integration_client.patch(
        "/api/me/profile",
        headers=auth_session.headers(csrf=False),
        json={},
    )
    assert response.status_code == 403, response.text
    assert response.json().get("code") != "rbac_denied"


@pytest.mark.integration
def test_rest_mutation_with_mismatched_csrf_header_is_rejected(integration_client, auth_session):
    headers = auth_session.headers()
    headers["X-CSRF-Token"] = "not-the-cookie-value"
    response = integration_client.patch("/api/me/profile", headers=headers, json={})
    assert response.status_code == 403, response.text


@pytest.mark.integration
def test_rest_mutation_with_matching_csrf_is_accepted(integration_client, auth_session):
    response = integration_client.patch(
        "/api/me/profile",
        headers=auth_session.headers(),
        json={},
    )
    assert response.status_code != 403, response.text
