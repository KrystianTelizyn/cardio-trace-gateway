from app.exceptions import AuthServiceException, InviteException
from auth0_server_python.error import AccessTokenError


def test_login_url_success(client):
    response = client.get("/url/auth0")
    assert response.status_code == 200
    data = response.json()
    assert data["login_url"] == "https://auth.example.com/authorize"


def test_login_url_auth_error_maps_to_502(client, gateway, mocker):
    mocker.patch.object(
        gateway.auth,
        "build_login_url",
        side_effect=AuthServiceException("Failed to build login URL"),
    )
    response = client.get("/url/auth0")
    assert response.status_code == 502
    assert response.json()["detail"] == "Failed to build login URL"


def test_callback_sets_csrf_cookie(client):
    response = client.get("/callback")
    assert response.status_code == 200
    assert "gateway_csrf=csrf-token" in response.headers.get("set-cookie", "")


def test_logout_clears_csrf_cookie(client):
    client.cookies.set("gateway_csrf", "csrf-token")
    response = client.post(
        "/logout",
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 200
    assert "gateway_csrf=" in response.headers.get("set-cookie", "")


def test_logout_rejects_without_csrf(client):
    response = client.post("/logout")
    assert response.status_code == 403


def test_invite_doctor_success(client):
    response = client.post(
        "/url/invite",
        json={"email": "doctor@example.com", "role": "doctor"},
    )
    assert response.status_code == 200
    assert "doctor@example.com" in response.json()["invite_url"]


def test_invite_exception_maps_to_502(client, gateway, mocker):
    mocker.patch.object(
        gateway.invites,
        "invite_patient",
        side_effect=InviteException("invite failed"),
    )
    response = client.post(
        "/url/invite",
        json={"email": "patient@example.com", "role": "patient"},
    )
    assert response.status_code == 502
    assert response.json()["detail"] == "invite failed"


def test_me_success(client):
    response = client.get("/me")
    assert response.status_code == 200
    data = response.json()
    assert data["sub"] == "user_123"
    assert data["org_id"] == "org_abc"
    assert data["permissions"] == ["read:patients"]
    assert data["roles"] == ["doctor"]
    assert data["email"] == "doctor@example.com"
    assert data["name"] == "Dr Example"
    assert data["picture"] == "https://example.com/avatar.png"


def test_me_rejects_unauthenticated(client, gateway, mocker):
    mocker.patch.object(
        gateway.auth,
        "get_access_token_from_session",
        side_effect=AccessTokenError("missing_token", "missing"),
    )
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_me_rejects_invalid_jwt(client, gateway):
    gateway.auth.session_token = "bad-token"
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired access token"


def test_me_allows_missing_identity_claims(client, gateway):
    gateway.auth.session_data = {"access_token": "example-access-token"}
    response = client.get("/me")
    assert response.status_code == 200
    data = response.json()
    assert data["email"] is None
    assert data["name"] is None
    assert data["picture"] is None


def test_healthz_success(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_success(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["checks"]["gateway"] is True


def test_readyz_not_ready(client):
    client.app.state.gateway = None
    response = client.get("/readyz")
    assert response.status_code == 503
    payload = response.json()["detail"]
    assert payload["status"] == "not_ready"
    assert payload["checks"]["gateway"] is False
