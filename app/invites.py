from config import Config
from auth0.management.management_client import ManagementClient

class Invites:
    def __init__(self):
        self.management_client = ManagementClient(
            domain=Config.AUTH0_DOMAIN,
            client_id=Config.API_EXPLORER_CLIENT_ID,
            client_secret=Config.API_EXPLORER_CLIENT_SECRET,
        )   

def invite_patient(self, email: str, ttl_sec: int = 3600) -> None:
    return self.invite_user(email,  Config.PATIENT_ROLE_ID, ttl_sec)

def invite_doctor(self, email: str, ttl_sec: int = 3600) -> None:
    return self.invite_user(email, Config.DOCTOR_ROLE_ID, ttl_sec)

def invite_user(self, email: str, role_id: str, ttl_sec: int = 3600) -> None:
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
    invitation_url = invitation_response.invitation_url.replace('https://cardio-trace.com', Config.INNER_AUTH_SERVICE_URL)
    return invitation_url
