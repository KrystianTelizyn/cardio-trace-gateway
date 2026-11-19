from collections.abc import Awaitable, Callable

from fastapi import Depends, Request, Response
from fastapi.security import APIKeyHeader

from app.exceptions import GatewayNotReadyError, RbacDeniedError
from app.gateway import Gateway
from app.gateway.jwt import TrustContext


csrf_header_scheme = APIKeyHeader(name="X-CSRF-Token", auto_error=False)

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
    return await gateway.auth.get_access_token_from_session(request, response)


def require_role(*allowed_roles: str) -> Callable[..., Awaitable[TrustContext]]:
    """FastAPI dependency: validate JWT and ensure ``TrustContext.role`` is allowed."""

    async def _dependency(
        request: Request,
        access_token: str = Depends(require_cookie_access_token),
        gateway: Gateway = Depends(get_gateway),
    ) -> TrustContext:
        ctx = gateway.jwt.build_trust_context(access_token)
        if ctx.role not in allowed_roles:
            raise RbacDeniedError(
                method=request.method,
                path=request.url.path,
                role=ctx.role,
            )
        return ctx

    return _dependency
