import secrets
from typing import Any

from fastapi import Request, Response
import jwt as pyjwt

from app.config import AuthSettings
from app.exceptions import AuthCallbackRedirectException, AuthServiceException, CsrfValidationError
from app.gateway.auth_redirects import AuthRedirectPolicy
from auth0_fastapi.stores import CookieTransactionStore, StatelessStateStore
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import LogoutOptions, StartInteractiveLoginOptions
from auth0_server_python.error import Auth0Error


class GatewayAuth:
    # Gateway-owned CSRF token cookie used for browser CSRF mitigation.
    # This cookie is intentionally readable by JS (httponly=False) to support
    # patterns like double-submit (SPA sends X-CSRF-Token header).
    _CSRF_COOKIE_NAME = "gateway_csrf"
    _CSRF_HEADER_NAME = "X-CSRF-Token"
    _CSRF_TOKEN_TTL_SEC = 3600
    _LOGIN_RETURN_TO_KEY = "return_to"
    _LOGIN_FLOW_TYPE_KEY = "flow_type"
    LOGIN_FLOW = "login"
    INVITE_ACCEPT_FLOW = "invite_accept"

    def __init__(self, settings: AuthSettings) -> None:
        """
        settings: Auth0 settings including optional frontend_url for CSRF cookie decisions.
        """
        self._settings = settings
        self._redirect_policy = AuthRedirectPolicy.from_auth_settings(settings)
        self._server_client = ServerClient(
            domain=settings.domain,
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            redirect_uri=settings.redirect_uri,
            secret=settings.secret,
            transaction_store=CookieTransactionStore(secret=settings.secret),
            state_store=StatelessStateStore(secret=settings.secret),
        )

    async def get_access_token_from_session(
        self, request: Request, response: Response
    ) -> str:
        """Return the API access token from the Auth0 cookie session (refreshing if needed)."""
        return await self._server_client.get_access_token(
            store_options={"request": request, "response": response},
            audience=self._settings.audience,
        )

    async def get_session_from_request(
        self, request: Request, response: Response
    ) -> Any:
        """Snapshot of Auth0 session data stored with the request (e.g. for debugging)."""
        return await self._server_client.get_session(
            store_options={"request": request, "response": response},
        )

    def get_identity_claims_from_session(self, session: Any) -> dict[str, str | None]:
        """
        Return normalized identity fields from Auth0 session data.

        Prefer already-parsed `user` claims from session state; when unavailable,
        decode `id_token` without signature verification as a best-effort fallback.
        """
        claims: dict[str, Any] = {}
        if isinstance(session, dict):
            user = session.get("user")
            if isinstance(user, dict):
                claims = user
            elif hasattr(user, "model_dump"):
                claims = user.model_dump()

            if not claims:
                id_token = session.get("id_token")
                if isinstance(id_token, str) and id_token:
                    try:
                        decoded = pyjwt.decode(
                            id_token,
                            options={
                                "verify_signature": False,
                                "verify_exp": False,
                                "verify_aud": False,
                                "verify_iss": False,
                            },
                            algorithms=["RS256", "HS256", "none"],
                        )
                        if isinstance(decoded, dict):
                            claims = decoded
                    except pyjwt.PyJWTError:
                        claims = {}

        return {
            "email": claims.get("email"),
            "name": claims.get("name"),
            "picture": claims.get("picture"),
        }

    async def _start_interactive_login(
        self,
        store_options: dict,
        return_to: str | None = None,
        flow_type: str = LOGIN_FLOW,
        authorization_params: dict[str, str] | None = None,
    ) -> str:
        request_authorization_params = {
            "response_type": "code",
            "client_id": self._settings.client_id,
            "redirect_uri": self._settings.redirect_uri,
            "scope": self._settings.scope,
            "audience": self._settings.audience,
        }
        if authorization_params:
            request_authorization_params.update(authorization_params)
        options = StartInteractiveLoginOptions(
            authorization_params=request_authorization_params,
            app_state={
                self._LOGIN_RETURN_TO_KEY: self._redirect_policy.normalize_return_to(return_to),
                self._LOGIN_FLOW_TYPE_KEY: flow_type,
            },
        )

        try:
            callback_url = await self._server_client.start_interactive_login(
                store_options=store_options,
                options=options,
            )
            return callback_url
        except Auth0Error as e:
            raise AuthServiceException("Failed to build login URL") from e

    async def build_login_url(
        self,
        store_options: dict,
        return_to: str | None = None,
    ) -> str:
        return await self._start_interactive_login(
            store_options=store_options,
            return_to=return_to,
            flow_type=self.LOGIN_FLOW,
        )

    async def build_invite_login_url(
        self,
        store_options: dict,
        invitation: str,
        organization: str,
        organization_name: str,
        return_to: str | None = None,
    ) -> str:
        return await self._start_interactive_login(
            store_options=store_options,
            return_to=return_to,
            flow_type=self.INVITE_ACCEPT_FLOW,
            authorization_params={
                "invitation": invitation,
                "organization": organization,
                "organization_name": organization_name,
            },
        )

    async def process_logout(
        self,
        store_options: dict,
        return_to: str | None = None,
    ) -> str:
        normalized = self._redirect_policy.normalize_return_to(return_to)
        logout_return_to = self._redirect_policy.build_frontend_absolute_url(normalized)
        try:
            return await self._server_client.logout(
                options=LogoutOptions(return_to=logout_return_to),
                store_options=store_options,
            )
        except Auth0Error as e:
            raise AuthServiceException("Logout failed") from e

    async def process_callback(self, callback_url: str, store_options: dict) -> dict:
        try:
            result = await self._server_client.complete_interactive_login(
                url=callback_url,
                store_options=store_options,
            )
            app_state = result.get("app_state") if isinstance(result, dict) else {}
            raw_return_to = (
                app_state.get(self._LOGIN_RETURN_TO_KEY) if isinstance(app_state, dict) else None
            )
            flow_type = (
                app_state.get(self._LOGIN_FLOW_TYPE_KEY) if isinstance(app_state, dict) else None
            )
            return {
                "success": True,
                "return_to": self._redirect_policy.normalize_return_to(raw_return_to),
                "flow_type": (
                    flow_type
                    if flow_type in {self.LOGIN_FLOW, self.INVITE_ACCEPT_FLOW}
                    else self.LOGIN_FLOW
                ),
            }
        except Auth0Error as e:
            raise AuthCallbackRedirectException() from e

    def success_redirect_url(self, return_to: str | None) -> str:
        """
        Frontend redirect for the successful Auth0 callback.

        Delegates URL building to the redirect policy.
        """
        return self._redirect_policy.build_callback_success_redirect_url(return_to)

    def error_redirect_url(self, code: str = "auth_callback_failed") -> str:
        """
        Frontend redirect for the failed Auth0 callback.

        Delegates URL building to the redirect policy.
        """
        return self._redirect_policy.build_callback_error_redirect_url(code=code)

    def set_csrf_token_cookie(self, response: Response) -> str:
        """
        Create/update the gateway-owned CSRF token cookie after successful login.

        """
        csrf_token = secrets.token_urlsafe(32)
        response.set_cookie(
            key=self._CSRF_COOKIE_NAME,
            value=csrf_token,
            max_age=self._CSRF_TOKEN_TTL_SEC,
            httponly=False,
            secure=self._redirect_policy.frontend_secure(),
            samesite="lax",
            path="/",
        )
        return csrf_token

    def clear_csrf_token_cookie(self, response: Response) -> None:
        """Remove the gateway-owned CSRF token cookie on logout."""
        response.delete_cookie(
            key=self._CSRF_COOKIE_NAME,
            path="/",
        )

    def validate_csrf_token(self, request: Request, csrf_protected_methods: set[str]) -> None:
        """
        Token-only CSRF mitigation for gateway proxy routes.

        For unsafe methods, requires `gateway_csrf` cookie value to match the
        `X-CSRF-Token` header (double-submit pattern).
        """
        if request.method not in csrf_protected_methods:
            return

        cookie_token = request.cookies.get(self._CSRF_COOKIE_NAME)
        header_token = request.headers.get(self._CSRF_HEADER_NAME)

        if not cookie_token or not header_token or cookie_token != header_token:
            raise CsrfValidationError("CSRF validation failed")

    def normalize_return_to(self, return_to: str | None) -> str:
        return self._redirect_policy.normalize_return_to(return_to)