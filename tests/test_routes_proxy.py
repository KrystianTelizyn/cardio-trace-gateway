import pytest
from app.exceptions import CsrfValidationError, JwtValidationError
from app.gateway.jwt import TrustContext
from starlette.responses import Response

_DOCTOR_CTX = TrustContext(user_id="auth0|abc", tenant_id="org_1", role="doctor")
_PATIENT_CTX = TrustContext(user_id="auth0|pat", tenant_id="org_1", role="patient")


@pytest.fixture(autouse=True)
def mock_access_token(mocker, gateway) -> str:
    mocker.patch.object(
        gateway.auth,
        "get_access_token_from_session",
        return_value="tokenabc",
    )
    return "tokenabc"


def test_rest_proxy_success(client, gateway, mocker):
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_DOCTOR_CTX)
    mock_response = Response(
        content=b"ok",
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
        "/api/devices?active=true",
        content=b'{"k":"v"}',
        headers={
            "X-CSRF-Token": "csrf-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 200
    gateway.router.api.assert_awaited_once()
    assert gateway.router.api.call_args.args[1] == "devices"


def test_graphql_proxy_success(client, gateway, mocker):
    client.cookies.set("gateway_csrf", "csrf-token")

    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_DOCTOR_CTX)
    mock_response = Response(
        content=b"graphql:example-access-token",
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
        headers={
            "X-CSRF-Token": "csrf-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "method,path,proxy_segment,ctx,csrf_required",
    [
        ("PATCH", "/api/me/profile", "me/profile", _DOCTOR_CTX, True),
        ("POST", "/api/devices", "devices", _DOCTOR_CTX, True),
        ("POST", "/api/device-assignments", "device-assignments", _DOCTOR_CTX, True),
        ("PATCH", "/api/device-assignments/da-1", "device-assignments/da-1", _DOCTOR_CTX, True),
        ("POST", "/api/measurement-sessions", "measurement-sessions", _PATIENT_CTX, True),
        ("PATCH", "/api/measurement-sessions/sess-1", "measurement-sessions/sess-1", _PATIENT_CTX, True),
    ],
)
def test_rest_proxy_route_matrix(
    client, gateway, mocker, method, path, proxy_segment, ctx, csrf_required
):
    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=ctx)
    mocker.patch.object(
        gateway.router,
        "api",
        mocker.AsyncMock(return_value=Response(content=b"ok", status_code=200)),
    )
    headers = {"content-type": "application/json"}
    if csrf_required:
        headers["X-CSRF-Token"] = "csrf-token"

    response = client.request(method, path, content=b'{"k":"v"}', headers=headers)

    assert response.status_code == 200
    gateway.router.api.assert_awaited_once()
    assert gateway.router.api.call_args.args[1] == proxy_segment


def test_rest_proxy_patch_without_payload_is_forwarded(client, gateway, mocker):
    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_DOCTOR_CTX)
    mocker.patch.object(
        gateway.router,
        "api",
        mocker.AsyncMock(return_value=Response(content=b"ok", status_code=200)),
    )

    response = client.patch("/api/me/profile", headers={"X-CSRF-Token": "csrf-token"})

    assert response.status_code == 200
    gateway.router.api.assert_awaited_once()
    assert gateway.router.api.call_args.args[1] == "me/profile"


def test_graphql_get_is_not_exposed(client, gateway, mocker):
    """GraphQL is POST-only at the edge: no CSRF-exempt read path to Hasura."""
    client.cookies.set("gateway_csrf", "csrf-token")
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_DOCTOR_CTX)
    mocker.patch.object(
        gateway.router,
        "graphql",
        mocker.AsyncMock(return_value=Response(content=b"ok", status_code=200)),
    )

    response = client.get("/graphql?query=%7Bme%7Bid%7D%7D")

    assert response.status_code == 405
    gateway.router.graphql.assert_not_awaited()


def test_rest_proxy_csrf_failure_maps_to_403(client, gateway, mocker):
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_DOCTOR_CTX)
    mocker.patch.object(
        gateway.auth,
        "validate_csrf_token",
        side_effect=CsrfValidationError("CSRF validation failed"),
    )
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/api/devices",
        content=b"{}",
        headers={
            "content-type": "application/json",
            "X-CSRF-Token": "csrf-token",
        },
    )
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
        headers={
            "X-CSRF-Token": "csrf-token",
            "content-type": "application/json",
        },
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
        "/api/devices",
        content=b'{"name":"x"}',
        headers={
            "X-CSRF-Token": "csrf-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired access token"


def test_rest_proxy_rbac_denied_maps_to_403_with_shape(client, gateway, mocker):
    mocker.patch.object(gateway.jwt, "build_trust_context", return_value=_PATIENT_CTX)
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/api/devices",
        content=b'{"status":"ack"}',
        headers={
            "X-CSRF-Token": "csrf-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 403
    assert response.json() == {
        "detail": "Forbidden",
        "code": "rbac_denied",
        "path": "/api/devices",
        "method": "POST",
    }
