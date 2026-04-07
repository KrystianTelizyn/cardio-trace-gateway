import pytest


@pytest.mark.integration
def test_rest_proxy_rejects_mutation_without_csrf(
    integration_client,
    integration_session_cookie,
    integration_inner_probe_path,
):
    if not integration_session_cookie:
        pytest.skip("Set INTEGRATION_SESSION_COOKIE to run authenticated proxy tests.")

    response = integration_client.post(
        f"/api/{integration_inner_probe_path}",
        headers={"Cookie": integration_session_cookie, "Content-Type": "application/json"},
        json={"probe": True},
    )
    assert response.status_code == 403


@pytest.mark.integration
def test_rest_proxy_accepts_mutation_with_matching_csrf(
    integration_client,
    integration_session_cookie,
    integration_csrf_token,
    integration_inner_probe_path,
):
    if not integration_session_cookie or not integration_csrf_token:
        pytest.skip(
            "Set INTEGRATION_SESSION_COOKIE and INTEGRATION_CSRF_TOKEN to run CSRF success test."
        )

    cookie_header = f"{integration_session_cookie}; gateway_csrf={integration_csrf_token}"
    response = integration_client.post(
        f"/api/{integration_inner_probe_path}",
        headers={
            "Cookie": cookie_header,
            "X-CSRF-Token": integration_csrf_token,
            "Content-Type": "application/json",
        },
        json={"probe": True},
    )
    assert response.status_code != 403, response.text
