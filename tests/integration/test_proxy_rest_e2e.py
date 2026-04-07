import pytest


@pytest.mark.integration
def test_rest_proxy_with_real_session_cookie(
    integration_client,
    integration_session_cookie,
    integration_inner_probe_path,
):
    if not integration_session_cookie:
        pytest.skip("Set INTEGRATION_SESSION_COOKIE to run authenticated proxy tests.")

    response = integration_client.get(
        f"/api/{integration_inner_probe_path}",
        headers={"Cookie": integration_session_cookie},
    )
    assert response.status_code not in (401, 403), response.text
