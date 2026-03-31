import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import Request, Response

from app.config import AuthSettings
from app.exceptions import AuthServiceException, CsrfValidationError
from auth0_fastapi.stores import CookieTransactionStore, StatelessStateStore
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import StartInteractiveLoginOptions
from auth0_server_python.error import Auth0Error


class GatewayAuth:
    # Gateway-owned CSRF token cookie used for browser CSRF mitigation.
    # This cookie is intentionally readable by JS (httponly=False) to support
    # patterns like double-submit (SPA sends X-CSRF-Token header).
    _CSRF_COOKIE_NAME = "gateway_csrf"
    _CSRF_HEADER_NAME = "X-CSRF-Token"
    _CSRF_TOKEN_TTL_SEC = 3600

    def __init__(self, settings: AuthSettings) -> None:
        """
        settings: Auth0 settings including optional frontend_url for CSRF cookie decisions.
        """
        self._settings = settings
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

    async def build_login_url(
        self,
        store_options: dict,
        invitation: str | None = None,
        organization: str | None = None,
        organization_name: str | None = None,
    ) -> str:
        authorization_params = {
            "response_type": "code",
            "client_id": self._settings.client_id,
            "redirect_uri": self._settings.redirect_uri,
            "scope": self._settings.scope,
            "audience": self._settings.audience,
        }
        if invitation and organization and organization_name:
            authorization_params["invitation"] = invitation
            authorization_params["organization"] = organization
            authorization_params["organization_name"] = organization_name
        options = StartInteractiveLoginOptions(authorization_params=authorization_params)

        try:
            callback_url = await self._server_client.start_interactive_login(
                store_options=store_options,
                options=options,
            )
            return callback_url
        except Auth0Error as e:
            raise AuthServiceException("Failed to build login URL") from e

    async def process_logout(self, store_options: dict) -> str:
        try:
            return await self._server_client.logout(store_options=store_options)
        except Auth0Error as e:
            raise AuthServiceException("Logout failed") from e

    async def process_callback(self, callback_url: str, store_options: dict) -> dict:
        try:
            result = await self._server_client.complete_interactive_login(
                url=callback_url,
                store_options=store_options,
            )
            return {"success": True}
        except Auth0Error as e:
            raise AuthServiceException("Failed to process callback") from e

    def _csrf_cookie_secure(self) -> bool:
        """
        Keep the cookie secure in production (https frontends).

        On localhost/dev we default to insecure to avoid breaking local testing.
        """
        frontend_url = self._settings.frontend_url or ""
        if not frontend_url:
            return False
        return urlparse(frontend_url).scheme == "https"

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
            secure=self._csrf_cookie_secure(),
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
