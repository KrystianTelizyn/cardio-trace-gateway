from typing import Any

import jwt
from jwt import PyJWKClient

from app.config import JwtSettings
from app.exceptions import JwtValidationError

# Small tolerance for exp/nbf across skewed clocks (Auth0 access tokens often include several audiences in `aud`).
_JWT_DECODE_LEEWAY_SEC = 60


def _normalize_auth0_issuer(url: str) -> str:
    """Auth0 tokens use a trailing slash on `iss` (e.g. https://tenant.auth0.com/)."""
    return url.rstrip("/") + "/"


class GatewayJwt:
    """
    Validates Auth0-issued JWT access tokens (RS256 via tenant JWKS).

    Access tokens may include `aud` as an array (API identifier + userinfo, etc.).
    ``AUTH0_AUDIENCE`` must match the API Resource Identifier present in that array
    (e.g. ``https://cardio-trace-api``). Custom namespaced claims (roles, permissions)
    are returned in the decoded dict unchanged.
    """

    def __init__(self, settings: JwtSettings) -> None:
        self._settings = settings
        issuer_raw = settings.issuer or f"https://{settings.domain}"
        self._issuer = _normalize_auth0_issuer(issuer_raw)
        self._audience = settings.audience
        self._jwks_client = PyJWKClient(f"https://{settings.domain}/.well-known/jwks.json")

    def validate_access_token(self, token: str) -> dict[str, Any]:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=_JWT_DECODE_LEEWAY_SEC,
            )
        except jwt.exceptions.PyJWTError as e:
            raise JwtValidationError(str(e)) from e
