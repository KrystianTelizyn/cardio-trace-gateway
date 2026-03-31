from app.exceptions import CsrfValidationError, JwtValidationError


def test_rest_proxy_success(client):
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/api/users?active=true",
        content=b'{"k":"v"}',
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 200
    assert "api:users:example-access-token" in response.text


def test_graphql_proxy_success(client):
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/graphql",
        content=b'{"query":"{ me { id } }"}',
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 200
    assert "graphql:example-access-token" in response.text


def test_rest_proxy_csrf_failure_maps_to_403(client, gateway, mocker):
    mocker.patch.object(
        gateway.auth,
        "validate_csrf_token",
        side_effect=CsrfValidationError("CSRF validation failed"),
    )
    response = client.post("/api/users", content=b"{}")
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed"


def test_graphql_proxy_jwt_failure_maps_to_401(client, gateway, mocker):
    mocker.patch.object(
        gateway.jwt,
        "validate_access_token",
        side_effect=JwtValidationError("bad token"),
    )
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/graphql",
        content=b'{"query":"{ me { id } }"}',
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired access token"
