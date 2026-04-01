from fastapi import Request
from fastapi.responses import JSONResponse

from app.exceptions import (
    AuthServiceException,
    CsrfValidationError,
    GatewayNotReadyError,
    InviteException,
    JwtValidationError,
)


async def jwt_validation_error_handler(
    _request: Request,
    _exc: JwtValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid or expired access token"},
    )


async def auth_service_exception_handler(
    _request: Request,
    exc: AuthServiceException,
) -> JSONResponse:
    """Auth0 interactive session / ServerClient failures (login URL, callback, logout)."""
    return JSONResponse(
        status_code=502,
        content={"detail": exc.message},
    )


async def invite_exception_handler(
    _request: Request,
    exc: InviteException,
) -> JSONResponse:
    """Auth0 Management API failures when creating organization invitations."""
    return JSONResponse(
        status_code=502,
        content={"detail": exc.message},
    )


async def csrf_validation_error_handler(
    _request: Request,
    exc: CsrfValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"detail": exc.message},
    )


async def gateway_not_ready_error_handler(
    _request: Request,
    exc: GatewayNotReadyError,
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "detail": {
                "status": "not_ready",
                "checks": exc.checks,
            }
        },
    )
