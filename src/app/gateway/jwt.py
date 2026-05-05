from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient

from app.config import JwtSettings
from app.exceptions import JwtValidationError

# Small tolerance for exp/nbf across skewed clocks (Auth0 access tokens often include several audiences in `aud`).
_JWT_DECODE_LEEWAY_SEC = 60

_ROLES_CLAIM_NAMESPACE = "https://cardio-trace.com/roles"


@dataclass(frozen=True)
class TrustContext:
    """Identity context extracted from a validated JWT, forwarded to upstream services."""

    user_id: str
    tenant_id: str
    role: str


def _normalize_auth0_issuer(url: str) -> str:
    """Auth0 tokens use a trailing slash on `iss` (e.g. https://tenant.auth0.com/)."""
    return url.rstrip("/") + "/"


def roles_from_claims(claims: dict[str, Any]) -> list[str]:
    """Extract roles from the namespaced or plain ``roles`` claim."""
    namespaced = claims.get(_ROLES_CLAIM_NAMESPACE)
    if isinstance(namespaced, list) and namespaced:
        return [str(r) for r in namespaced]
    plain = claims.get("roles")
    if isinstance(plain, list) and plain:
        return [str(r) for r in plain]
    return []


def _extract_role(claims: dict[str, Any]) -> str:
    """Return the first role from claims, or raise."""
    roles = roles_from_claims(claims)
    if not roles:
        raise JwtValidationError("No role found in token claims")
    return roles[0]


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

    def build_trust_context(self, token: str) -> TrustContext:
        """Validate *token* and return a :class:`TrustContext` for upstream headers."""
        claims = self.validate_access_token(token)
        sub = claims.get("sub")
        org_id = claims.get("org_id")
        if not sub:
            raise JwtValidationError("Missing 'sub' claim in access token")
        if not org_id:
            raise JwtValidationError("Missing 'org_id' claim in access token")
        return TrustContext(
            user_id=str(sub),
            tenant_id=str(org_id),
            role=_extract_role(claims),
        )
