import pytest
from types import SimpleNamespace

import jwt
from app.config import JwtSettings
from app.exceptions import JwtValidationError
from app.gateway.jwt import (
    GatewayJwt,
    TrustContext,
    _JWT_DECODE_LEEWAY_SEC,
    _normalize_auth0_issuer,
    roles_from_claims,
)


@pytest.fixture
def auth0_shaped_claims() -> dict[str, object]:
    """Decoded access-token claims shaped like Auth0 + Cardio Trace custom claims."""
    return {
        "https://cardio-trace.com/roles": ["doctor"],
        "iss": "https://tenant.auth0.com/",
        "sub": "auth0|69c67fbae0fe4c8e4c710082",
        "aud": ["https://cardio-trace-api", "https://tenant.auth0.com/userinfo"],
        "iat": 1774860387,
        "exp": 1774946787,
        "scope": "openid profile email offline_access",
        "org_id": "org_nBep3mlTxl2DlaNs",
        "jti": "mCX2XvbgKdC6S3zqw5Pp7m",
        "client_id": "LsXD3o91KL6DeOcDXphSiZNzoi7qZZHq",
        "permissions": ["read:patients", "write:patients"],
    }


def _make_validator(mocker, decoded_claims):
    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    mocker.patch("app.gateway.jwt.jwt.decode", return_value=decoded_claims)
    settings = JwtSettings(
        domain="tenant.auth0.com",
        audience="https://cardio-trace-api",
        issuer="https://tenant.auth0.com/",
    )
    return GatewayJwt(settings)


def test_normalize_auth0_issuer():
    assert _normalize_auth0_issuer("https://tenant.auth0.com") == "https://tenant.auth0.com/"
    assert _normalize_auth0_issuer("https://tenant.auth0.com/") == "https://tenant.auth0.com/"


def test_validate_access_token_success_with_auth0_shaped_claims(
    mocker, example_access_token, auth0_shaped_claims: dict[str, object]
):
    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    decode = mocker.patch("app.gateway.jwt.jwt.decode", return_value=auth0_shaped_claims)

    settings = JwtSettings(
        domain="tenant.auth0.com",
        audience="https://cardio-trace-api",
        issuer="https://tenant.auth0.com/",
    )
    validator = GatewayJwt(settings)
    claims = validator.validate_access_token(example_access_token)

    assert claims["sub"] == "auth0|69c67fbae0fe4c8e4c710082"
    assert claims["aud"] == ["https://cardio-trace-api", "https://tenant.auth0.com/userinfo"]
    assert claims["https://cardio-trace.com/roles"] == ["doctor"]
    assert claims["permissions"] == ["read:patients", "write:patients"]
    jwk_cls.return_value.get_signing_key_from_jwt.assert_called_once_with(example_access_token)
    decode.assert_called_once_with(
        example_access_token,
        "public-key",
        algorithms=["RS256"],
        audience="https://cardio-trace-api",
        issuer="https://tenant.auth0.com/",
        leeway=_JWT_DECODE_LEEWAY_SEC,
    )


def test_validate_access_token_raises_jwt_validation_error(mocker, example_access_token):
    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    mocker.patch(
        "app.gateway.jwt.jwt.decode",
        side_effect=jwt.exceptions.InvalidTokenError("decode failure"),
    )

    settings = JwtSettings(
        domain="tenant.auth0.com",
        audience="https://api.example.com",
        issuer="https://tenant.auth0.com/",
    )
    validator = GatewayJwt(settings)
    with pytest.raises(JwtValidationError):
        validator.validate_access_token(example_access_token)


# --- build_trust_context ---

def test_build_trust_context_extracts_claims(mocker, example_access_token, auth0_shaped_claims: dict[str, object]):
    validator = _make_validator(mocker, auth0_shaped_claims)
    ctx = validator.build_trust_context(example_access_token)

    assert ctx == TrustContext(
        user_id="auth0|69c67fbae0fe4c8e4c710082",
        tenant_id="org_nBep3mlTxl2DlaNs",
        role="doctor",
    )


def test_build_trust_context_uses_plain_roles_claim(mocker, example_access_token, auth0_shaped_claims: dict[str, object]):
    auth0_shaped_claims.pop("https://cardio-trace.com/roles")
    auth0_shaped_claims["roles"] = ["patient"]
    validator = _make_validator(mocker, auth0_shaped_claims)
    ctx = validator.build_trust_context(example_access_token)

    assert ctx.role == "patient"


def test_build_trust_context_raises_on_missing_sub(mocker, example_access_token, auth0_shaped_claims: dict[str, object]):
    auth0_shaped_claims.pop("sub")
    validator = _make_validator(mocker, auth0_shaped_claims)

    with pytest.raises(JwtValidationError, match="sub"):
        validator.build_trust_context(example_access_token)


def test_build_trust_context_raises_on_missing_org_id(mocker, example_access_token, auth0_shaped_claims: dict[str, object]):
    auth0_shaped_claims.pop("org_id")
    validator = _make_validator(mocker, auth0_shaped_claims)

    with pytest.raises(JwtValidationError, match="org_id"):
        validator.build_trust_context(example_access_token)


def test_build_trust_context_raises_on_missing_roles(mocker, example_access_token, auth0_shaped_claims: dict[str, object]):
    auth0_shaped_claims.pop("https://cardio-trace.com/roles")
    validator = _make_validator(mocker, auth0_shaped_claims)

    with pytest.raises(JwtValidationError, match="role"):
        validator.build_trust_context(example_access_token)


def test_roles_from_claims_prefers_namespaced_claim():
    claims = {
        "https://cardio-trace.com/roles": ["doctor"],
        "roles": ["patient"],
    }
    assert roles_from_claims(claims) == ["doctor"]


def test_roles_from_claims_falls_back_to_plain_roles():
    claims = {
        "roles": ["patient", "doctor"],
    }
    assert roles_from_claims(claims) == ["patient", "doctor"]


def test_roles_from_claims_coerces_values_to_strings():
    claims = {
        "https://cardio-trace.com/roles": [1, "doctor"],
    }
    assert roles_from_claims(claims) == ["1", "doctor"]


@pytest.mark.parametrize(
    "claims",
    [
        {"https://cardio-trace.com/roles": []},
        {"https://cardio-trace.com/roles": "doctor"},
        {"roles": []},
        {"roles": "doctor"},
        {},
    ],
)
def test_roles_from_claims_returns_empty_for_invalid_or_missing_claims(claims):
    assert roles_from_claims(claims) == []


def test_validate_access_token_normalizes_issuer_without_trailing_slash(
    mocker, example_access_token, auth0_shaped_claims: dict[str, object]
):
    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    decode = mocker.patch("app.gateway.jwt.jwt.decode", return_value=auth0_shaped_claims)

    settings = JwtSettings(
        domain="tenant.auth0.com",
        audience="https://cardio-trace-api",
        issuer="https://tenant.auth0.com",
    )
    validator = GatewayJwt(settings)
    validator.validate_access_token(example_access_token)

    decode.assert_called_once_with(
        example_access_token,
        "public-key",
        algorithms=["RS256"],
        audience="https://cardio-trace-api",
        issuer="https://tenant.auth0.com/",
        leeway=_JWT_DECODE_LEEWAY_SEC,
    )


def test_validate_access_token_raises_when_jwk_fetch_fails(mocker, example_access_token):
    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    jwk_cls.return_value.get_signing_key_from_jwt.side_effect = jwt.exceptions.PyJWKClientError("jwks failure")

    settings = JwtSettings(
        domain="tenant.auth0.com",
        audience="https://api.example.com",
        issuer="https://tenant.auth0.com/",
    )
    validator = GatewayJwt(settings)
    with pytest.raises(JwtValidationError, match="jwks failure"):
        validator.validate_access_token(example_access_token)
