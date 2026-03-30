import pytest
from types import SimpleNamespace

import jwt
from app.exceptions import JwtValidationError
from app.gateway.jwt import GatewayJwt, _normalize_auth0_issuer


def test_normalize_auth0_issuer():
    assert _normalize_auth0_issuer("https://tenant.auth0.com") == "https://tenant.auth0.com/"
    assert _normalize_auth0_issuer("https://tenant.auth0.com/") == "https://tenant.auth0.com/"


def test_validate_access_token_success_with_mocked_jwks_flow(mocker, monkeypatch, example_access_token):
    monkeypatch.setattr("app.gateway.jwt.Config.AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setattr("app.gateway.jwt.Config.AUTH0_AUDIENCE", "https://api.example.com")
    monkeypatch.setattr("app.gateway.jwt.Config.AUTH0_ISSUER", "https://tenant.auth0.com")

    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    decode = mocker.patch("app.gateway.jwt.jwt.decode", return_value={"sub": "user_1", "aud": "https://api.example.com"})

    validator = GatewayJwt()
    claims = validator.validate_access_token(example_access_token)

    assert claims["sub"] == "user_1"
    jwk_cls.return_value.get_signing_key_from_jwt.assert_called_once_with(example_access_token)
    decode.assert_called_once()


def test_validate_access_token_raises_jwt_validation_error(mocker, monkeypatch, example_access_token):
    monkeypatch.setattr("app.gateway.jwt.Config.AUTH0_DOMAIN", "tenant.auth0.com")
    monkeypatch.setattr("app.gateway.jwt.Config.AUTH0_AUDIENCE", "https://api.example.com")
    monkeypatch.setattr("app.gateway.jwt.Config.AUTH0_ISSUER", "https://tenant.auth0.com")

    jwk_cls = mocker.patch("app.gateway.jwt.PyJWKClient")
    signing_key = SimpleNamespace(key="public-key")
    jwk_cls.return_value.get_signing_key_from_jwt.return_value = signing_key
    mocker.patch(
        "app.gateway.jwt.jwt.decode",
        side_effect=jwt.exceptions.InvalidTokenError("decode failure"),
    )

    validator = GatewayJwt()
    with pytest.raises(JwtValidationError):
        validator.validate_access_token(example_access_token)
