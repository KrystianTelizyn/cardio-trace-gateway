from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from app.deps import get_auth_service, require_cookie_access_token
from app.service import AuthService
from app.schemas import (
    CallbackResponse,
    InviteRequest,
    InviteResponse,
    InviteRole,
    LoginUrlRequest,
    LoginUrlResponse,
    LogoutResponse,
)
router = APIRouter()

@router.get("/url/auth0", response_model=LoginUrlResponse)
async def login(
    request: Request,
    response: Response,
    payload: LoginUrlRequest = Depends(),
    auth_service: AuthService = Depends(get_auth_service),
) -> LoginUrlResponse:

    login_url = await auth_service.build_login_url(
        invitation=payload.invitation,
        organization=payload.organization,
        organization_name=payload.organization_name,
        store_options={
            "request": request,
            "response": response,
        }
    )

    return LoginUrlResponse(login_url=login_url, message="Follow the link to initiate login.")

@router.get("/callback", response_model=CallbackResponse)
async def callback(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
) -> CallbackResponse:

    await auth_service.process_callback(
        callback_url=str(request.url),
        store_options={
            "request": request,
            "response": response,
        }
    )
    return CallbackResponse(success=True, message="Authentication successful, tokens set in cookie.")

@router.get("/logout", response_model=LogoutResponse)
async def logout(
    request: Request, 
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
) -> LogoutResponse:
    await auth_service.process_logout(
        store_options={
            "request": request,
            "response": response,
        }
    )
    return LogoutResponse(logout=True, message="Logout successful.")

@router.post("/url/invite", response_model=InviteResponse)
async def invite(
    payload: InviteRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> InviteResponse:
    if payload.role == InviteRole.patient:
        invite_url = auth_service.invite_patient(str(payload.email))
    elif payload.role == InviteRole.doctor:
        invite_url = auth_service.invite_doctor(str(payload.email))
    else:
        raise HTTPException(status_code=400, detail="Invalid role.")
    return InviteResponse(invite_url=invite_url, message="User invited. Follow the link to complete the invitation.")


_GATEWAY_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@router.api_route("/api/", methods=_GATEWAY_HTTP_METHODS, tags=["gateway"])
@router.api_route("/api/{proxy_path:path}", methods=_GATEWAY_HTTP_METHODS, tags=["gateway"])
async def gateway_rest_proxy_placeholder(
    request: Request,
    proxy_path: str = "",
    _access_token: str = Depends(require_cookie_access_token),
):
    """Placeholder for forwarding to the hidden REST API; requires Auth0 cookie session."""
    return JSONResponse(
        content={
            "status": "placeholder",
            "gateway": "rest",
            "method": request.method,
            "upstream_path": proxy_path or "",
        }
    )


@router.api_route("/graphql", methods=["GET", "POST"], tags=["gateway"])
async def gateway_graphql_placeholder(
    request: Request,
    _access_token: str = Depends(require_cookie_access_token),
):
    """Placeholder for GraphQL proxy; requires Auth0 cookie session."""
    return JSONResponse(
        content={
            "status": "placeholder",
            "gateway": "graphql",
            "method": request.method,
        }
    )



# This is a debug endpoint to reveal the tokens in the cookie
@router.get("/reveal-tokens")
async def reveal_tokens(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    session = await auth_service.server_client.get_session(
        store_options={
            "request": request,
            "response": response,
        }
    )
    return JSONResponse(content=session)