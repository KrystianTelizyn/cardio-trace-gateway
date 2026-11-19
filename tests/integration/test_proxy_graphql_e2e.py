import pytest


@pytest.mark.integration
def test_graphql_proxy_with_real_session(
    integration_client,
    auth_session,
    integration_graphql_probe_query,
):
    response = integration_client.post(
        "/graphql",
        headers=auth_session.headers(),
        json={"query": integration_graphql_probe_query},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "errors" not in payload, payload
    assert "data" in payload


@pytest.mark.integration
def test_graphql_post_without_csrf_is_rejected(
    integration_client,
    auth_session,
    integration_graphql_probe_query,
):
    response = integration_client.post(
        "/graphql",
        headers=auth_session.headers(csrf=False),
        json={"query": integration_graphql_probe_query},
    )
    assert response.status_code == 403, response.text


@pytest.mark.integration
def test_graphql_get_is_not_exposed(integration_client, auth_session):
    response = integration_client.get(
        "/graphql",
        params={"query": "{__typename}"},
        headers=auth_session.headers(),
    )
    assert response.status_code == 405, response.text
