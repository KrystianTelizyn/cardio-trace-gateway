from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from app.deps import get_gateway, require_cookie_access_token, csrf_api, csrf_graphql
from app.gateway import Gateway
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
    gateway: Gateway = Depends(get_gateway),
) -> LoginUrlResponse:
    login_url = await gateway.auth.build_login_url(
        invitation=payload.invitation,
        organization=payload.organization,
        organization_name=payload.organization_name,
        store_options={
            "request": request,
            "response": response,
        },
    )
    return LoginUrlResponse(login_url=login_url, message="Follow the link to initiate login.")


@router.get("/callback", response_model=CallbackResponse)
async def callback(
    request: Request,
    response: Response,
    gateway: Gateway = Depends(get_gateway),
) -> CallbackResponse:
    await gateway.auth.process_callback(
        callback_url=str(request.url),
        store_options={
            "request": request,
            "response": response,
        },
    )
    gateway.auth.set_csrf_token_cookie(response)
    return CallbackResponse(success=True, message="Authentication successful, tokens set in cookie.")


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
) -> LogoutResponse:
    logout_url = await gateway.auth.process_logout(
        store_options={
            "request": request,
            "response": response,
        },
    )
    gateway.auth.clear_csrf_token_cookie(response)
    return LogoutResponse(
        logout=True,
        logout_url=logout_url,
        message="Logout successful.",
    )


@router.post("/url/invite", response_model=InviteResponse)
async def invite(
    payload: InviteRequest,
    gateway: Gateway = Depends(get_gateway),
) -> InviteResponse:
    if payload.role == InviteRole.patient:
        invite_url = gateway.invites.invite_patient(str(payload.email))
    else:
        invite_url = gateway.invites.invite_doctor(str(payload.email))
    return InviteResponse(
        invite_url=invite_url,
        message="User invited. Follow the link to complete the invitation.",
    )


_GATEWAY_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@router.api_route("/api/{proxy_path:path}", methods=_GATEWAY_HTTP_METHODS, tags=["gateway"])
async def gateway_rest_proxy(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    gateway.jwt.validate_access_token(access_token)
    return await gateway.router.api(request, proxy_path, access_token)


@router.api_route("/graphql", methods=["GET", "POST"], tags=["gateway"])
async def gateway_graphql(
    request: Request,
    access_token: str = Depends(require_cookie_access_token),
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
):
    gateway.jwt.validate_access_token(access_token)
    return await gateway.router.graphql(request, access_token)


@router.get("/reveal-tokens")
async def reveal_tokens(
    request: Request,
    response: Response,
    gateway: Gateway = Depends(get_gateway),
):
    session = await gateway.auth.get_session_from_request(request, response)
    return JSONResponse(content=session)
