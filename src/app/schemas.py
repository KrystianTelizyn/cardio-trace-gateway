from enum import Enum

from pydantic import BaseModel, EmailStr


class LoginUrlRequest(BaseModel):
    return_to: str | None = None


class InviteLoginUrlRequest(BaseModel):
    invitation: str
    organization: str
    organization_name: str
    return_to: str | None = None


class LoginUrlResponse(BaseModel):
    login_url: str
    message: str

class CallbackResponse(BaseModel):
    success: bool
    message: str


class LogoutRequest(BaseModel):
    """Optional body for POST /logout; return_to is normalized server-side."""

    return_to: str | None = None


class LogoutResponse(BaseModel):
    logout: bool
    logout_url: str
    message: str


class InviteRole(str, Enum):
    patient = "patient"
    doctor = "doctor"


class InviteRequest(BaseModel):
    email: EmailStr
    role: InviteRole
    return_to: str | None = None


class InviteResponse(BaseModel):
    invite_url: str
    message: str


class MeResponse(BaseModel):
    sub: str | None = None
    org_id: str | None = None
    scope: str | None = None
    permissions: list[str] = []
    roles: list[str] = []
    email: str | None = None
    name: str | None = None
    picture: str | None = None


class UserRegistrationPayload(BaseModel):
    """Payload sent to the inner API when an invited user completes registration."""

    auth0_user_id: str
    auth0_org_id: str
    role: str
    email: str
    name: str


class HealthResponse(BaseModel):
    status: str


class ReadinessResponse(BaseModel):
    status: str
    checks: dict[str, bool]