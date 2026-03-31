import pytest
from types import SimpleNamespace

import jwt
from app.config import JwtSettings
from app.exceptions import JwtValidationError
from app.gateway.jwt import GatewayJwt, _JWT_DECODE_LEEWAY_SEC, _normalize_auth0_issuer


def test_normalize_auth0_issuer():
    assert _normalize_auth0_issuer("https://tenant.auth0.com") == "https://tenant.auth0.com/"
    assert _normalize_auth0_issuer("https://tenant.auth0.com/") == "https://tenant.auth0.com/"


def test_validate_access_token_success_with_auth0_shaped_claims(mocker, example_access_token):
    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    decoded_claims = {
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
    decode = mocker.patch("app.gateway.jwt.jwt.decode", return_value=decoded_claims)

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
