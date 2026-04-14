import pytest
from app.exceptions import CsrfValidationError, JwtValidationError
from app.gateway.jwt import TrustContext
from starlette.responses import Response

_STUB_CTX = TrustContext(user_id="auth0|abc", tenant_id="org_1", role="doctor")


@pytest.fixture(autouse=True)
def mock_access_token(mocker, gateway) -> str:
    mocker.patch.object(
        gateway.auth,
        "get_access_token_from_session",
        return_value="tokenabc",
    )
    return "tokenabc"

def test_rest_proxy_success(client, gateway, mocker):
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_STUB_CTX)
    mock_response = Response(
        content="api:users:example-access-token",
        status_code=200,
        media_type="text/plain",
    )

    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(
        gateway.router,
        "api",
        mocker.AsyncMock(return_value=mock_response),
    )
    response = client.post(
        "/api/users?active=true",
        content=b'{"k":"v"}',
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 200


def test_graphql_proxy_success(client, gateway, mocker):
    client.cookies.set("gateway_csrf", "csrf-token")

    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_STUB_CTX)
    mock_response = Response(
        content="graphql:example-access-token",
        status_code=200,
        media_type="text/plain",
    )
    mocker.patch.object(
        gateway.router,
        "graphql",
        mocker.AsyncMock(return_value=mock_response),
    )

    response = client.post(
        "/graphql",
        content=b'{"query":"{ me { id } }"}',
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 200


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
        "build_trust_context",
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
