from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import Response

from app.error_handlers import (
    auth_service_exception_handler,
    csrf_validation_error_handler,
    gateway_not_ready_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import (
    AuthServiceException,
    CsrfValidationError,
    GatewayNotReadyError,
    InviteException,
    JwtValidationError,
)
from app.routes import router


class FakeAuth:
    def __init__(self) -> None:
        self.session_token = "example-access-token"
        self.session_data: dict[str, Any] = {
            "access_token": "example-access-token",
            "id_token": "header.payload.signature",
            "user": {
                "email": "doctor@example.com",
                "name": "Dr Example",
                "picture": "https://example.com/avatar.png",
            },
        }

    async def get_access_token_from_session(self, request, response) -> str:
        return self.session_token

    async def get_session_from_request(self, request, response):
        return self.session_data

    def get_identity_claims_from_session(self, session) -> dict[str, str | None]:
        user = session.get("user", {}) if isinstance(session, dict) else {}
        return {
            "email": user.get("email"),
            "name": user.get("name"),
            "picture": user.get("picture"),
        }

    async def build_login_url(self, **kwargs) -> str:
        return "https://auth.example.com/authorize"

    async def process_callback(self, callback_url: str, store_options: dict) -> dict:
        return {"success": True}

    async def process_logout(self, store_options: dict) -> str:
        return "https://auth.example.com/logout"

    def set_csrf_token_cookie(self, response) -> str:
        token = "csrf-token"
        response.set_cookie("gateway_csrf", token)
        return token

    def clear_csrf_token_cookie(self, response) -> None:
        response.delete_cookie("gateway_csrf")

    def validate_csrf_token(self, request, csrf_protected_methods: set[str]) -> None:
        if request.method not in csrf_protected_methods:
            return
        cookie_token = request.cookies.get("gateway_csrf")
        header_token = request.headers.get("X-CSRF-Token")
        if not cookie_token or cookie_token != header_token:
            raise CsrfValidationError("CSRF validation failed")


class FakeJwt:
    def __init__(self) -> None:
        self.last_validated: str | None = None

    def validate_access_token(self, token: str) -> dict[str, Any]:
        self.last_validated = token
        if token == "bad-token":
            raise JwtValidationError("invalid token")
        return {
            "sub": "user_123",
            "org_id": "org_abc",
            "scope": "openid profile",
            "permissions": ["read:patients"],
            "https://cardio-trace.com/roles": ["doctor"],
        }


class FakeRouter:
    async def api(self, request, proxy_path: str, access_token: str):
        return Response(
            content=f"api:{proxy_path}:{access_token}",
            status_code=200,
            media_type="text/plain",
        )

    async def graphql(self, request, access_token: str):
        return Response(
            content=f"graphql:{access_token}",
            status_code=200,
            media_type="text/plain",
        )


class FakeInvites:
    def invite_patient(self, email: str, ttl_sec: int = 3600) -> str:
        return f"https://invite.example.com/patient?email={email}"

    def invite_doctor(self, email: str, ttl_sec: int = 3600) -> str:
        return f"https://invite.example.com/doctor?email={email}"


class FakeGateway:
    def __init__(self) -> None:
        self.auth = FakeAuth()
        self.jwt = FakeJwt()
        self.router = FakeRouter()
        self.invites = FakeInvites()

    def ensure_ready(self) -> dict[str, bool]:
        checks = {
            "gateway": True,
            "auth": hasattr(self, "auth"),
            "jwt": hasattr(self, "jwt"),
            "router": hasattr(self, "router"),
            "invites": hasattr(self, "invites"),
        }
        if not all(checks.values()):
            raise GatewayNotReadyError(checks=checks)
        return checks


@pytest.fixture
def example_access_token() -> str:
    # Placeholder fixture for swapping in a real token sample.
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"


@pytest.fixture
def gateway() -> FakeGateway:
    return FakeGateway()


@pytest.fixture
def app(gateway: FakeGateway) -> FastAPI:
    app = FastAPI()
    app.add_exception_handler(JwtValidationError, jwt_validation_error_handler)
    app.add_exception_handler(AuthServiceException, auth_service_exception_handler)
    app.add_exception_handler(InviteException, invite_exception_handler)
    app.add_exception_handler(CsrfValidationError, csrf_validation_error_handler)
    app.add_exception_handler(GatewayNotReadyError, gateway_not_ready_error_handler)
    app.include_router(router)
    app.state.gateway = gateway
    return app


@pytest.fixture
def client(app: FastAPI):
    with TestClient(app) as test_client:
        yield test_client
