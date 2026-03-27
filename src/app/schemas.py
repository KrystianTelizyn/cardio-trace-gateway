from enum import Enum

from pydantic import BaseModel, EmailStr


class LoginUrlRequest(BaseModel):
    invitation: str | None = None
    organization: str | None = None
    organization_name: str | None = None


class LoginUrlResponse(BaseModel):
    login_url: str
    message: str

class CallbackResponse(BaseModel):
    success: bool
    message: str

class LogoutResponse(BaseModel):
    logout: bool
    message: str


class InviteRole(str, Enum):
    patient = "patient"
    doctor = "doctor"


class InviteRequest(BaseModel):
    email: EmailStr
    role: InviteRole


class InviteResponse(BaseModel):
    invite_url: str
    message: str