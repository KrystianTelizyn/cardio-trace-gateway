import pytest

from app.exceptions import InviteException
from app.gateway.invites import Invites
from auth0.management.core import ApiError


@pytest.fixture
def invites(mocker, monkeypatch):
    monkeypatch.setattr("app.gateway.invites.Config.AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setattr("app.gateway.invites.Config.API_EXPLORER_CLIENT_ID", "id")
    monkeypatch.setattr("app.gateway.invites.Config.API_EXPLORER_CLIENT_SECRET", "secret")
    monkeypatch.setattr("app.gateway.invites.Config.PATIENT_ROLE_ID", "role_patient")
    monkeypatch.setattr("app.gateway.invites.Config.DOCTOR_ROLE_ID", "role_doctor")
    monkeypatch.setattr("app.gateway.invites.Config.CARDIO_TRACE_CLINIC_ID", "org_1")
    monkeypatch.setattr("app.gateway.invites.Config.AUTH0_CLIENT_ID", "auth0_client")
    monkeypatch.setattr("app.gateway.invites.Config.CARDIO_TRACE_APPLICATION_LOGIN_URI", "https://login.example.com")
    monkeypatch.setattr("app.gateway.invites.Config.INVITE_URL_REPLACEMENT", "http://localhost:3000/login")
    mgmt = mocker.patch("app.gateway.invites.ManagementClient", autospec=True)
    service = Invites()
    return service, mgmt.return_value


def test_invite_patient_rewrites_invite_url(invites, mocker):
    service, mgmt_client = invites
    response = mocker.Mock()
    response.invitation_url = "https://login.example.com/invite?ticket=abc"
    mgmt_client.organizations.invitations.create.return_value = response

    url = service.invite_patient("patient@example.com")
    assert url.startswith("http://localhost:3000/login")


def test_invite_user_maps_api_error(invites):
    service, mgmt_client = invites
    mgmt_client.organizations.invitations.create.side_effect = ApiError(status_code=400, body={"message": "boom"})
    with pytest.raises(InviteException):
        service.invite_doctor("doctor@example.com")
