from fastapi import APIRouter, Request, Response
from fastapi import Depends, FastAPI
from app.service import AuthService
from fastapi.responses import RedirectResponse
from app.config import Config
router = APIRouter()

def get_auth_service(app: FastAPI):
    return app.state.auth_service

@router.get("/login")
async def login(
    auth_service: AuthService = Depends(get_auth_service),
    invitation: str = None,
    organization: str = None,
    organization_name: str = None,
    return_to: str = None
    ):
    if invitation and organization and organization_name:
        callback_url = await auth_service.process_login_from_invitation(
            invitation, 
            organization, 
            organization_name,
            return_to
        )
    else:
        callback_url = await auth_service.process_login(return_to)
    return RedirectResponse(callback_url)

@router.get("/callback")
async def callback(request: Request, auth_service: AuthService = Depends(get_auth_service)):
    result = await auth_service.process_callback(str(request.url))
    access_token = result.get("access_token")
    refresh_token = result.get("refresh_token")
    id_token = result.get("id_token")
    redirect_to = result.get("return_to")
    # TODO: Send tokens to client
    return RedirectResponse(Config.FRONTEND_URL + redirect_to, status_code=302)

@router.get("/logout")
async def logout(auth_service: AuthService = Depends(get_auth_service)):
    await auth_service.process_logout()
    return RedirectResponse(Config.FRONTEND_URL, status_code=302)

@router.post("/invite")
async def invite_patient(
    auth_service: AuthService = Depends(get_auth_service),
    email: str = Form(...),
    role: str = Form(...),
):
    if role == "patient":
        invite_url = auth_service.invite_patient(email)
    elif role == "doctor":
        invite_url = auth_service.invite_doctor(email)
    else:
        return {"error": "Invalid role"}
    return {"invite_url": invite_url}