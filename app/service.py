from app.config import Config
from auth0_server_python.auth_server.server_client import ServerClient
from app.invites import Invites

class AuthService:
    def __init__(self):
        self.server_client = ServerClient(
            domain=Config.AUTH0_DOMAIN, 
            client_id=Config.AUTH0_CLIENT_ID,
            client_secret=Config.AUTH0_CLIENT_SECRET,
            )
        self.invites = Invites()

    def invite_patient(self, email: str):
        return self.invites.invite_patient(email)
    
    def invite_doctor(self, email: str):
        return self.invites.invite_doctor(email)
    
    async def process_login_from_invitation(self, 
        return_to: str,
        invitation: str = None,
        organization: str = None,
        organization_name: str = None,
        ) -> str:
        try:
            callback_url = await self.server_client.start_interactive_login({
                "authorization_params": 
                {
                    "response_type": "code",
                    "client_id": Config.AUTH0_CLIENT_ID,
                    "redirect_uri": Config.AUTH0_REDIRECT_URI,
                    "scope": Config.AUTH0_SCOPE,
                    "audience": Config.AUTH0_AUDIENCE,
                    "invitation": invitation,
                    "organization": organization,
                    "organization_name": organization_name
                },
                "app_state": {
                    "return_to": return_to
                }
            })
            return callback_url
        except Exception as e:
            ...
    async def process_login(self, return_to: str) -> str:
        try:
            callback_url = await self.server_client.start_interactive_login({
                "authorization_params": 
                {
                    "response_type": "code",
                    "client_id": Config.AUTH0_CLIENT_ID,
                    "redirect_uri": Config.AUTH0_REDIRECT_URI,
                    "scope": Config.AUTH0_SCOPE,
                    "audience": Config.AUTH0_AUDIENCE,
                },
                "app_state": {
                    "return_to": return_to
                }
            })
            return callback_url
        except Exception as e:
            ...

    async def process_logout(self) -> None:
        try:
            await self.server_client.logout()
        except Exception as e:
            ...
    
    async def process_callback(self, callback_url: str) -> dict:
        try:
            result = await self.server_client.complete_interactive_login(callback_url)
            return_to = result.get("app_state").get("return_to")
            state_data = result.get("state_data")
            refresh_token = state_data.refresh_token
            id_token = state_data.id_token
            access_token = state_data.token_sets[0].access_token
            return {
                "return_to": return_to,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token
            }
        except Exception as e:
            ...