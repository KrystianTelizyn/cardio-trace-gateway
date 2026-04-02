from fastapi import APIRouter, Depends, Request, Response, Security
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
    LoginUrlRequest,
    LoginUrlResponse,
    LogoutResponse,
)

router = APIRouter()


@router.get("/me", response_model=MeResponse, tags=["Auth"])
async def me(
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


@router.get("/url/auth0", response_model=LoginUrlResponse,tags=["Auth"])
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
        return_to=payload.return_to,
        store_options={
            "request": request,
            "response": response,
        },
    )
    return LoginUrlResponse(login_url=login_url, message="Follow the link to initiate login.")


@router.get("/callback",tags=["Auth"])
async def callback(
    request: Request,
    gateway: Gateway = Depends(get_gateway),
) -> RedirectResponse:
    return await gateway.callback_redirect_response(request)


@router.post("/logout", response_model=LogoutResponse,tags=["Auth"])
async def logout(
    request: Request,
    response: Response,
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
) -> LogoutResponse:
    logout_url = await gateway.logout_user(request, response)
    return LogoutResponse(
        logout=True,
        logout_url=logout_url,
        message="Logout successful.",
    )


@router.post("/url/invite", response_model=InviteResponse,tags=["Invites"])
async def invite(
    payload: InviteRequest,
    gateway: Gateway = Depends(get_gateway),
) -> InviteResponse:
    invite_url = gateway.create_invite(str(payload.email), payload.role, payload.return_to)
    return InviteResponse(
        invite_url=invite_url,
        message="User invited. Follow the link to complete the invitation.",
    )


_GATEWAY_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@router.api_route("/api/{proxy_path:path}", methods=_GATEWAY_HTTP_METHODS, tags=["REST"])
async def gateway_rest_proxy(
    request: Request,
    proxy_path: str = "",
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_api),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_api(request, proxy_path, access_token)


@router.api_route("/graphql", methods=["GET", "POST"], tags=["GraphQL"])
async def gateway_graphql(
    request: Request,
    access_token: str = Depends(require_cookie_access_token),
    _csrf_doc: str | None = Security(csrf_header_scheme),
    _csrf_ok: None = Depends(csrf_graphql),
    gateway: Gateway = Depends(get_gateway),
):
    return await gateway.proxy_graphql(request, access_token)
