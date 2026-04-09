from fastapi import APIRouter, Body, Depends, Request, Response, Security
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse

from app.deps import get_gateway, require_cookie_access_token, csrf_api, csrf_graphql, csrf_header_scheme
from app.gateway import Gateway
from app.schemas import (
    InviteRequest,
    InviteResponse,
    MeResponse,
    HealthResponse,
    ReadinessResponse,
    InviteLoginUrlRequest,
    LoginUrlRequest,
    LoginUrlResponse,
    LogoutRequest,
    LogoutResponse,
)

router = APIRouter()


@router.get("/auth/me", response_model=MeResponse, tags=["Auth"])
async def auth_me(
    request: Request,
    response: Response,
    access_token: str = Depends(require_cookie_access_token),
    gateway: Gateway = Depends(get_gateway),
) -> MeResponse:
    return MeResponse(**(await gateway.get_me(request, response, access_token)))


@router.get("/healthz", response_model=HealthResponse, tags=["Health"])
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=ReadinessResponse, tags=["Health"])
async def readyz(gateway: Gateway = Depends(get_gateway)) -> ReadinessResponse:
    checks = gateway.ensure_ready()
    return ReadinessResponse(status="ok", checks=checks)


@router.get("/auth/login-url", response_model=LoginUrlResponse, tags=["Auth"])
async def get_login_url(
    request: Request,
    response: Response,
    payload: LoginUrlRequest = Depends(),
    gateway: Gateway = Depends(get_gateway),
) -> LoginUrlResponse:
    login_url = await gateway.auth.build_login_url(
        return_to=payload.return_to,
        store_options={
            "request": request,
            "response": response,
        },
    )
    return LoginUrlResponse(login_url=login_url, message="Follow the link to initiate login.")


@router.get("/auth/invite-login-url", response_model=LoginUrlResponse, tags=["Auth"])
async def get_invite_login_url(
    request: Request,
    response: Response,
    payload: InviteLoginUrlRequest = Depends(),
    gateway: Gateway = Depends(get_gateway),
) -> LoginUrlResponse:
    login_url = await gateway.auth.build_invite_login_url(
        invitation=payload.invitation,
        organization=payload.organization,
        organization_name=payload.organization_name,
        return_to=payload.return_to,
        store_options={
            "request": request,
            "response": response,
        },
    )
    return LoginUrlResponse(login_url=login_url, message="Follow the link to initiate login.")


@router.get("/auth/callback", tags=["Auth"])
async def auth_callback(
    request: Request,
    gateway: Gateway = Depends(get_gateway),
) -> RedirectResponse:
    return await gateway.callback_redirect_response(request)


@router.post("/auth/logout", response_model=LogoutResponse, tags=["Auth"])
async def auth_logout(
    request: Request,
    response: Response,
    payload: LogoutRequest | None = Body(default=None),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
) -> LogoutResponse:
    return_to = payload.return_to if payload is not None else None
    logout_url = await gateway.logout_user(
        request, response, return_to=return_to
    )
    return LogoutResponse(
        logout=True,
        logout_url=logout_url,
        message="Logout successful. Sesion invalidated. Follow the link to complete the logout.",
    )


@router.post("/invites", response_model=InviteResponse, tags=["Invites"])
async def create_invite(
    payload: InviteRequest,
    gateway: Gateway = Depends(get_gateway),
) -> InviteResponse:
    invite_url = gateway.create_invite(str(payload.email), payload.role, payload.return_to)
    return InviteResponse(
        invite_url=invite_url,
        message="User invited. Follow the link to complete the invitation.",
    )

@router.get("/api/{proxy_path:path}", tags=["REST"])
async def gateway_rest_proxy_get(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_api(request, proxy_path, access_token)

@router.post("/api/{proxy_path:path}", tags=["REST"])
async def gateway_rest_proxy_post(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_api(request, proxy_path, access_token)

@router.put("/api/{proxy_path:path}", tags=["REST"])
async def gateway_rest_proxy_put(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_api(request, proxy_path, access_token)

@router.patch("/api/{proxy_path:path}", tags=["REST"])
async def gateway_rest_proxy_patch(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_api(request, proxy_path, access_token)

@router.delete("/api/{proxy_path:path}", tags=["REST"])
async def gateway_rest_proxy_delete(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_api(request, proxy_path, access_token)

@router.get("/graphql", tags=["GraphQL"])
async def gateway_graphql_get(
    request: Request,
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_graphql(request, access_token)

@router.post("/graphql", tags=["GraphQL"])
async def gateway_graphql_post(
    request: Request,
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_graphql(request, access_token)