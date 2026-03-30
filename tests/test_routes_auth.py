from app.exceptions import AuthServiceException, InviteException


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
    response = client.get("/logout")
    assert response.status_code == 200
    assert "gateway_csrf=" in response.headers.get("set-cookie", "")


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
