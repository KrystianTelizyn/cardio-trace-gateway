from urllib.parse import parse_qs, urlparse

import pytest

from app.config import InviteSettings
from app.exceptions import InviteException
from app.gateway.invites import Invites
from auth0.management.core import ApiError


@pytest.fixture
def invites(mocker):
    settings = InviteSettings(
        auth0_domain="tenant.auth0.com",
        cardio_trace_clinic_id="org_1",
        patient_role_id="role_patient",
        doctor_role_id="role_doctor",
        api_explorer_client_id="id",
        api_explorer_client_secret="secret",
        auth0_client_id="auth0_client",
        cardio_trace_application_login_uri="https://login.example.com",
        invite_url_replacement="http://localhost:3000/login",
    )
    mgmt = mocker.patch("app.gateway.invites.ManagementClient", autospec=True)
    service = Invites(settings)
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


def test_invite_user_calls_management_client_with_expected_params(invites, mocker):
    service, mgmt_client = invites
    response = mocker.Mock()
    response.invitation_url = "https://login.example.com/invite?ticket=xyz"
    mgmt_client.organizations.invitations.create.return_value = response

    service.invite_user(
        "member@example.com",
        role_id="role_custom",
        normalized_return_to=None,
        ttl_sec=900,
    )

    mgmt_client.organizations.invitations.create.assert_called_once_with(
        id="org_1",
        inviter={"name": "Cardio Trace Admin"},
        invitee={"email": "member@example.com"},
        client_id="auth0_client",
        ttl_sec=900,
        roles=["role_custom"],
        send_invitation_email=False,
    )


def test_invite_user_appends_return_to_query_when_normalized_return_to_set(invites, mocker):
    service, mgmt_client = invites
    response = mocker.Mock()
    response.invitation_url = "https://login.example.com/invite?ticket=abc"
    mgmt_client.organizations.invitations.create.return_value = response

    url = service.invite_user(
        "member@example.com",
        role_id="role_custom",
        normalized_return_to="/dashboard",
    )

    qs = parse_qs(urlparse(url).query)
    assert qs.get("return_to") == ["/dashboard"]


def test_invite_user_omits_return_to_when_normalized_return_to_is_root_path(invites, mocker):
    service, mgmt_client = invites
    response = mocker.Mock()
    response.invitation_url = "https://login.example.com/invite?ticket=abc"
    mgmt_client.organizations.invitations.create.return_value = response

    url = service.invite_user(
        "member@example.com",
        role_id="role_custom",
        normalized_return_to="/",
    )

    assert "return_to" not in urlparse(url).query


def test_invite_patient_uses_patient_role_id_from_settings(invites, mocker):
    service, _ = invites
    invite_user_spy = mocker.patch.object(service, "invite_user", return_value="ignored")

    service.invite_patient("patient@example.com")

    invite_user_spy.assert_called_once_with(
        "patient@example.com",
        role_id="role_patient",
        normalized_return_to=None,
        ttl_sec=3600,
    )


def test_invite_patient_forwards_normalized_return_to(invites, mocker):
    service, _ = invites
    invite_user_spy = mocker.patch.object(service, "invite_user", return_value="ignored")

    service.invite_patient("patient@example.com", normalized_return_to="/after-login", ttl_sec=7200)

    invite_user_spy.assert_called_once_with(
        "patient@example.com",
        role_id="role_patient",
        normalized_return_to="/after-login",
        ttl_sec=7200,
    )


def test_invite_doctor_uses_doctor_role_id_from_settings(invites, mocker):
    service, _ = invites
    invite_user_spy = mocker.patch.object(service, "invite_user", return_value="ignored")

    service.invite_doctor("doctor@example.com")

    invite_user_spy.assert_called_once_with(
        "doctor@example.com",
        role_id="role_doctor",
        normalized_return_to=None,
        ttl_sec=3600,
    )


def test_invite_doctor_forwards_normalized_return_to(invites, mocker):
    service, _ = invites
    invite_user_spy = mocker.patch.object(service, "invite_user", return_value="ignored")

    service.invite_doctor("doctor@example.com", normalized_return_to="/clinic", ttl_sec=7200)

    invite_user_spy.assert_called_once_with(
        "doctor@example.com",
        role_id="role_doctor",
        normalized_return_to="/clinic",
        ttl_sec=7200,
    )
