from app.config import InviteSettings
from auth0.management.management_client import ManagementClient
from auth0.management.core import ApiError
from app.exceptions import InviteException


class Invites:
    def __init__(self, settings: InviteSettings):
        self._settings = settings
        self.management_client = ManagementClient(
            domain=settings.cardio_trace_clinic_id,  # domain is often Auth0 tenant; adjust when wiring
            client_id=settings.api_explorer_client_id,
            client_secret=settings.api_explorer_client_secret,
        )

    def invite_patient(self, email: str, ttl_sec: int = 3600) -> str:
        return self.invite_user(email, self._settings.patient_role_id, ttl_sec)

    def invite_doctor(self, email: str, ttl_sec: int = 3600) -> str:
        return self.invite_user(email, self._settings.doctor_role_id, ttl_sec)

    def invite_user(self, email: str, role_id: str, ttl_sec: int = 3600) -> str:
        try:
            invitation_response = self.management_client.organizations.invitations.create(
                id=self._settings.cardio_trace_clinic_id,
                inviter={
                    "name": "Cardio Trace Admin"
                },
                invitee={
                    "email": email
                },
                client_id=self._settings.auth0_client_id,
                ttl_sec=ttl_sec,
                roles=[role_id],
                send_invitation_email=False,
            )
            replacement = self._settings.invite_url_replacement
            invitation_url = invitation_response.invitation_url.replace(
                self._settings.cardio_trace_application_login_uri,
                replacement,
            )
            return invitation_url
        except ApiError as e:
            raise InviteException(f"Failed to generate invitation for {email} as {role_id}") from e
