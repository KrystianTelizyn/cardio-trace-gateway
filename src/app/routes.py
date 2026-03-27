from fastapi import APIRouter, Request, Response
from fastapi import Depends
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
from fastapi import HTTPException
router = APIRouter()

def get_auth_service(request: Request):
    return request.app.state.auth_service

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


from fastapi.responses import JSONResponse

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