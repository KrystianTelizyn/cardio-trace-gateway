from app.config import Config
from auth0.management.management_client import ManagementClient
from auth0.management.core import ApiError
from app.exceptions import InviteException

class Invites:
    def __init__(self):
        self.management_client = ManagementClient(
            domain=Config.AUTH0_DOMAIN,
            client_id=Config.API_EXPLORER_CLIENT_ID,
            client_secret=Config.API_EXPLORER_CLIENT_SECRET,
        )   

    def invite_patient(self, email: str, ttl_sec: int = 3600) -> str:
        return self.invite_user(email,  Config.PATIENT_ROLE_ID, ttl_sec)

    def invite_doctor(self, email: str, ttl_sec: int = 3600) -> str:
        return self.invite_user(email, Config.DOCTOR_ROLE_ID, ttl_sec)

    def invite_user(self, email: str, role_id: str, ttl_sec: int = 3600) -> str:
        try:
            invitation_response = self.management_client.organizations.invitations.create(
                id=Config.CARDIO_TRACE_CLINIC_ID,
                inviter={
                    "name": "Cardio Trace Admin"
                },
                invitee={
                    "email": email
                },
                client_id=Config.AUTH0_CLIENT_ID,
                ttl_sec=ttl_sec,
                roles=[role_id],
                send_invitation_email=False,
            )
            invitation_url = invitation_response.invitation_url.replace(Config.CARDIO_TRACE_APPLICATION_LOGIN_URI, Config.INVITE_URL_REPLACEMENT)
            return invitation_url
        except ApiError as e:
            raise InviteException(f"Failed to generate invitation for {email} as {role_id}") from e
