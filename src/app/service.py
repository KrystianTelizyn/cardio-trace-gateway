from app.config import Config
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import StartInteractiveLoginOptions
from app.invites import Invites
from auth0_fastapi.stores import CookieTransactionStore, StatelessStateStore
from auth0_server_python.error import Auth0Error
from app.exceptions import AuthServiceException, InviteException

class AuthService:
    def __init__(self):
        self.server_client = ServerClient(
            domain=Config.AUTH0_DOMAIN, 
            client_id=Config.AUTH0_CLIENT_ID,
            client_secret=Config.AUTH0_CLIENT_SECRET,
            redirect_uri=Config.AUTH0_REDIRECT_URI,
            secret=Config.AUTH0_SECRET,
            transaction_store=CookieTransactionStore(secret=Config.AUTH0_SECRET),
            state_store=StatelessStateStore(secret=Config.AUTH0_SECRET),
            )
        self.invites = Invites()

    def invite_patient(self, email: str):
        try:
            return self.invites.invite_patient(email)
        except InviteException as e:
            raise AuthServiceException("Failed to invite patient") from e
    
    def invite_doctor(self, email: str):
        try:
            return self.invites.invite_doctor(email)
        except InviteException as e:
            raise AuthServiceException("Failed to invite doctor") from e
    
    async def build_login_url(self, 
        store_options: dict,
        invitation: str = None,
        organization: str = None,
        organization_name: str = None,
        ) -> str:
        authorization_params = {
            "response_type": "code",
            "client_id": Config.AUTH0_CLIENT_ID,
            "redirect_uri": Config.AUTH0_REDIRECT_URI,
            "scope": Config.AUTH0_SCOPE,
            "audience": Config.AUTH0_AUDIENCE
        }
        if invitation and organization and organization_name:
            authorization_params["invitation"] = invitation
            authorization_params["organization"] = organization
            authorization_params["organization_name"] = organization_name
        options = StartInteractiveLoginOptions(
            authorization_params=authorization_params
        )
        print(options)
        try:
            callback_url = await self.server_client.start_interactive_login(
                store_options=store_options,
                options=options,
            )
            return callback_url
        except Auth0Error as e:
            raise AuthServiceException("Failed to build login URL") from e


    async def process_logout(self, store_options: dict) -> None:
        try:
            await self.server_client.logout(
                store_options=store_options,
            )
        except Auth0Error as e:
            raise AuthServiceException("Logout failed") from e
    
    async def process_callback(self, callback_url: str, store_options: dict) -> dict:
        try:
            result = await self.server_client.complete_interactive_login(
                url=callback_url,
                store_options=store_options,
            )
            print(result.get("state_data"))
            return {"success": True}
        except Auth0Error as e:
            raise AuthServiceException("Failed to process callback") from e