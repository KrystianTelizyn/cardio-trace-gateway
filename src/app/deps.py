from fastapi import Depends, HTTPException, Request, Response

from app.config import Config
from app.service import AuthService
from auth0_server_python.error import AccessTokenError


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


async def require_cookie_access_token(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
) -> str:
    """
    Ensures the Auth0 session cookie yields a usable access token (refreshes if needed).
    """
    try:
        return await auth_service.server_client.get_access_token(
            store_options={"request": request, "response": response},
            audience=Config.AUTH0_AUDIENCE,
        )
    except AccessTokenError:
        raise HTTPException(status_code=401, detail="Not authenticated")
