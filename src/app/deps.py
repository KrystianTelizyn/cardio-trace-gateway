from fastapi import Depends, HTTPException, Request, Response

from app.exceptions import GatewayNotReadyError
from app.gateway import Gateway
from auth0_server_python.error import AccessTokenError


def get_gateway(request: Request) -> Gateway:
    gateway = getattr(request.app.state, "gateway", None)
    if gateway is None:
        raise GatewayNotReadyError(
            checks={
                "gateway": False,
                "auth": False,
                "jwt": False,
                "router": False,
                "invites": False,
            }
        )
    return gateway


def csrf_api(request: Request, gateway: Gateway = Depends(get_gateway)) -> None:
    """Token-only CSRF validation for state-changing REST proxy requests."""
    gateway.auth.validate_csrf_token(
        request,
        csrf_protected_methods={"POST", "PUT", "PATCH", "DELETE"},
    )


def csrf_graphql(request: Request, gateway: Gateway = Depends(get_gateway)) -> None:
    """Token-only CSRF validation for GraphQL POST requests."""
    gateway.auth.validate_csrf_token(
        request,
        csrf_protected_methods={"POST"},
    )


async def require_cookie_access_token(
    request: Request,
    response: Response,
    gateway: Gateway = Depends(get_gateway),
) -> str:
    """
    Ensures the Auth0 session cookie yields a usable access token (refreshes if needed).
    """
    try:
        return await gateway.auth.get_access_token_from_session(request, response)
    except AccessTokenError:
        raise HTTPException(status_code=401, detail="Not authenticated")
