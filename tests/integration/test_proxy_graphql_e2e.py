import pytest


@pytest.mark.integration
def test_graphql_proxy_with_real_session_cookie(
    integration_client,
    integration_session_cookie,
    integration_graphql_probe_query,
):
    if not integration_session_cookie:
        pytest.skip("Set INTEGRATION_SESSION_COOKIE to run authenticated proxy tests.")

    response = integration_client.post(
        "/graphql",
        headers={
            "Cookie": integration_session_cookie,
            "Content-Type": "application/json",
        },
        json={"query": integration_graphql_probe_query},
    )
    assert response.status_code not in (401, 403), response.text
