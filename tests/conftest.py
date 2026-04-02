from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import RedirectResponse
from starlette.responses import Response

from auth0_server_python.error import AccessTokenError

from app.error_handlers import (
    access_token_error_handler,
    auth_callback_redirect_exception_handler,
    auth_service_exception_handler,
    csrf_validation_error_handler,
    gateway_not_ready_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import (
    AuthCallbackRedirectException,
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
        return {"success": True, "return_to": "/dashboard"}

    def success_redirect_url(self, return_to: str | None) -> str:
        next_path = return_to or "/"
        return f"https://frontend.example.com/auth/callback/success?next={next_path}"

    def error_redirect_url(self, code: str = "auth_callback_failed") -> str:
        return f"https://frontend.example.com/auth/callback/error?code={code}"

    async def process_logout(
        self,
        store_options: dict,
        return_to: str | None = None,
    ) -> str:
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

    @staticmethod
    def _roles_from_claims(claims: dict[str, Any]) -> list[str]:
        if isinstance(claims.get("roles"), list):
            return [str(role) for role in claims["roles"]]
        for key, value in claims.items():
            if key.endswith("/roles") and isinstance(value, list):
                return [str(role) for role in value]
        return []

    async def get_me(self, request, response, access_token: str) -> dict[str, Any]:
        claims = self.jwt.validate_access_token(access_token)
        session = await self.auth.get_session_from_request(request, response)
        identity = self.auth.get_identity_claims_from_session(session)
        return {
            "sub": claims.get("sub"),
            "org_id": claims.get("org_id"),
            "scope": claims.get("scope"),
            "permissions": [str(p) for p in claims.get("permissions", []) if isinstance(p, str)],
            "roles": self._roles_from_claims(claims),
            "email": identity.get("email"),
            "name": identity.get("name"),
            "picture": identity.get("picture"),
        }

    async def complete_callback(self, request, response) -> str:
        callback_result = await self.auth.process_callback(
            callback_url=str(request.url),
            store_options={"request": request, "response": response},
        )
        self.auth.set_csrf_token_cookie(response)
        return callback_result.get("return_to", "/")

    async def callback_redirect_response(self, request):
        success_redirect = RedirectResponse(
            url=self.auth.success_redirect_url(return_to="/"),
            status_code=302,
        )
        return_to = await self.complete_callback(request, success_redirect)
        success_redirect.headers["location"] = self.auth.success_redirect_url(
            return_to=return_to
        )
        return success_redirect

    async def logout_user(
        self,
        request,
        response,
        return_to: str | None = None,
    ) -> str:
        logout_url = await self.auth.process_logout(
            store_options={"request": request, "response": response},
            return_to=return_to,
        )
        self.auth.clear_csrf_token_cookie(response)
        return logout_url

    def create_invite(self, email: str, role: str, return_to: str | None = None) -> str:
        if role == "patient":
            return self.invites.invite_patient(email)
        return self.invites.invite_doctor(email)

    async def proxy_api(self, request, proxy_path: str, access_token: str):
        self.jwt.validate_access_token(access_token)
        return await self.router.api(request, proxy_path, access_token)

    async def proxy_graphql(self, request, access_token: str):
        self.jwt.validate_access_token(access_token)
        return await self.router.graphql(request, access_token)

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
    app.add_exception_handler(AccessTokenError, access_token_error_handler)
    app.add_exception_handler(AuthCallbackRedirectException, auth_callback_redirect_exception_handler)
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
