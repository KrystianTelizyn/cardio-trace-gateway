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
    gateway.router.api.assert_awaited_once()
    assert gateway.router.api.call_args.args[1] == "users"


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


@pytest.mark.parametrize(
    "method,path,csrf_required",
    [
        ("GET", "/api/patients/123/visits", False),
        ("PUT", "/api/patients/123/visits", True),
        ("PATCH", "/api/patients/123/visits", True),
        ("DELETE", "/api/patients/123/visits", True),
    ],
)
def test_rest_proxy_route_matrix(client, gateway, mocker, method, path, csrf_required):
    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_STUB_CTX)
    mocker.patch.object(
        gateway.router,
        "api",
        mocker.AsyncMock(return_value=Response(content="ok", status_code=200)),
    )
    headers = {"content-type": "application/json"}
    if csrf_required:
        headers["X-CSRF-Token"] = "csrf-token"

    response = client.request(method, path, content=b'{"k":"v"}', headers=headers)

    assert response.status_code == 200
    gateway.router.api.assert_awaited_once()
    assert gateway.router.api.call_args.args[1] == "patients/123/visits"


def test_rest_proxy_patch_without_payload_is_forwarded(client, gateway, mocker):
    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_STUB_CTX)
    mocker.patch.object(
        gateway.router,
        "api",
        mocker.AsyncMock(return_value=Response(content="ok", status_code=200)),
    )

    response = client.patch("/api/patients/123", headers={"X-CSRF-Token": "csrf-token"})

    assert response.status_code == 200
    gateway.router.api.assert_awaited_once()
    assert gateway.router.api.call_args.args[1] == "patients/123"


def test_graphql_get_proxy_success_without_csrf(client, gateway, mocker):
    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_STUB_CTX)
    mocker.patch.object(
        gateway.router,
        "graphql",
        mocker.AsyncMock(return_value=Response(content="ok", status_code=200)),
    )

    response = client.get("/graphql?query=%7Bme%7Bid%7D%7D")

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


def test_rest_proxy_jwt_failure_maps_to_401(client, gateway, mocker):
    mocker.patch.object(
        gateway.jwt,
        "build_trust_context",
        side_effect=JwtValidationError("bad token"),
    )
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/api/users",
        content=b'{"name":"x"}',
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired access token"
