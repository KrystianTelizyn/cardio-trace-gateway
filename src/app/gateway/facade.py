import logging
from typing import Any, Self

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from starlette.responses import Response as StarletteResponse

import httpx

from app.config import AppSettings
from app.exceptions import GatewayNotReadyError, InviteRegistrationError
from app.gateway.auth import GatewayAuth
from app.gateway.invites import Invites
from app.gateway.jwt import GatewayJwt, roles_from_claims
from app.gateway.router import GatewayRouter
from app.schemas import InviteRole, UserRegistrationPayload


class Gateway:
    _logger = logging.getLogger(__name__)

    def __init__(self, settings: AppSettings) -> None:
        """
        Aggregate gateway facade wired with explicit settings.

        The application should construct AppSettings.from_env() once at startup
        and pass it here.
        """
        self.settings = settings
        self.auth = GatewayAuth(settings.auth)
        self.jwt = GatewayJwt(settings.jwt)
        self.invites = Invites(settings.invites)
        self.router = GatewayRouter(settings.router)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: object | None,
    ) -> None:
        await self.router.aclose()

    def readiness_checks(self) -> dict[str, bool]:
        return {
            "gateway": True,
            "auth": hasattr(self, "auth"),
            "jwt": hasattr(self, "jwt"),
            "router": hasattr(self, "router"),
            "invites": hasattr(self, "invites"),
        }

    def ensure_ready(self) -> dict[str, bool]:
        checks = self.readiness_checks()
        if not all(checks.values()):
            raise GatewayNotReadyError(checks=checks)
        return checks

    async def get_me(self, request: Request, response: Response, access_token: str) -> dict[str, Any]:
        claims = self.jwt.validate_access_token(access_token)
        session = await self.auth.get_session_from_request(request, response)
        identity = self.auth.get_identity_claims_from_session(session)
        return {
            "sub": claims.get("sub"),
            "org_id": claims.get("org_id"),
            "scope": claims.get("scope"),
            "permissions": [str(p) for p in claims.get("permissions", []) if isinstance(p, str)],
            "roles": roles_from_claims(claims),
            "email": identity.get("email"),
            "name": identity.get("name"),
            "picture": identity.get("picture"),
        }

    async def complete_callback(self, request: Request, response: Response) -> dict[str, Any]:
        callback_result = await self.auth.process_callback(
            callback_url=str(request.url),
            store_options={
                "request": request,
                "response": response,
            },
        )
        self.auth.set_csrf_token_cookie(response)
        return {
            "return_to": str(callback_result.get("return_to", "/")),
            "flow_type": str(callback_result.get("flow_type", self.auth.LOGIN_FLOW)),
            "user_claims": callback_result.get("user_claims"),
        }

    @staticmethod
    def _build_user_registration_payload(claims: dict[str, Any]) -> UserRegistrationPayload:
        roles = roles_from_claims(claims)
        if not roles:
            raise InviteRegistrationError("No role found in user claims during invite registration")
        return UserRegistrationPayload(
            auth0_user_id=claims.get("sub", ""),
            auth0_org_id=claims.get("org_id", ""),
            role=roles[0],
            email=claims.get("email", ""),
            name=claims.get("name", ""),
        )

    async def _notify_invite_registration_completed(self, user_data: dict[str, Any]) -> None:
        try:
            payload = self._build_user_registration_payload(user_data)
            response = await self.router.request_internal(
                "POST", "/users", json=payload.model_dump(),
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise InviteRegistrationError(
                f"Inner API rejected user registration: {exc.response.status_code}"
            ) from exc


    async def callback_redirect_response(self, request: Request) -> RedirectResponse:
        success_redirect = RedirectResponse(
            url=self.auth.success_redirect_url(return_to="/"),
            status_code=302,
        )
        callback_result = await self.complete_callback(request, success_redirect)
        if callback_result.get("flow_type") == self.auth.INVITE_ACCEPT_FLOW:
            await self._notify_invite_registration_completed(callback_result.get("user_claims"))
        success_redirect.headers["location"] = self.auth.success_redirect_url(
            return_to=str(callback_result.get("return_to", "/"))
        )
        return success_redirect

    async def logout_user(
        self,
        request: Request,
        response: Response,
        return_to: str | None = None,
    ) -> str:
        logout_url = await self.auth.process_logout(
            store_options={
                "request": request,
                "response": response,
            },
            return_to=return_to,
        )
        self.auth.clear_csrf_token_cookie(response)
        return logout_url

    def create_invite(self, email: str, role: InviteRole, return_to: str | None = None) -> str:
        normalized_return_to = self.auth.normalize_return_to(return_to)
        if role == InviteRole.patient:
            return self.invites.invite_patient(email, normalized_return_to)
        return self.invites.invite_doctor(email, normalized_return_to)

    async def proxy_api(
        self,
        request: Request,
        proxy_path: str,
        access_token: str,
    ) -> StarletteResponse:
        ctx = self.jwt.build_trust_context(access_token)
        return await self.router.api(request, proxy_path, ctx)

    async def proxy_graphql(self, request: Request, access_token: str) -> StarletteResponse:
        ctx = self.jwt.build_trust_context(access_token)
        return await self.router.graphql(request, ctx)
