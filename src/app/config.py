from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from app.exceptions import ConfigError

class Env:
    """
    Small wrapper around an environment mapping.

    - Normalises empty strings -> None
    - Supports `required=True` to fail fast
    - Makes it easy to inject a fake env in tests
    """

    def __init__(self, environ: Mapping[str, str]):
        self._environ = environ

    def __call__(self, key: str, *, required: bool = True) -> str | None:
        value = self._environ.get(key)
        if value is not None:
            value = value.strip() or None

        if required and value is None:
            raise ConfigError(f"Missing required environment variable: {key}")

        return value

@dataclass(frozen=True)
class AuthSettings:
    """
    Settings for Auth0 interactive session / ServerClient flows (`GatewayAuth`).
    """

    domain: str
    audience: str
    client_id: str
    client_secret: str
    redirect_uri: str
    secret: str
    scope: str
    frontend_url: str
    callback_success_path: str = "/auth/callback/success"
    callback_error_path: str = "/auth/callback/error"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "AuthSettings":
        env = Env(environ)
        return cls(
            domain=env("AUTH0_DOMAIN"),
            audience=env("AUTH0_AUDIENCE"),
            client_id=env("AUTH0_CLIENT_ID"),
            client_secret=env("AUTH0_CLIENT_SECRET"),
            redirect_uri=env("AUTH0_REDIRECT_URI"),
            secret=env("AUTH0_SECRET"),
            scope=env("AUTH0_SCOPE"),
            frontend_url=env("FRONTEND_URL"),
            callback_success_path=env("AUTH_CALLBACK_SUCCESS_PATH", required=False)
            or "/auth/callback/success",
            callback_error_path=env("AUTH_CALLBACK_ERROR_PATH", required=False)
            or "/auth/callback/error",
        )


@dataclass(frozen=True)
class InviteSettings:
    """
    Settings for Auth0 Management / invitation flows (`Invites`).
    """

    auth0_domain: str
    cardio_trace_clinic_id: str
    patient_role_id: str
    doctor_role_id: str
    api_explorer_client_id: str
    api_explorer_client_secret: str
    auth0_client_id: str
    cardio_trace_application_login_uri: str
    invite_url_replacement: str

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "InviteSettings":
        env = Env(environ)
        return cls(
            auth0_domain=env("AUTH0_DOMAIN"),
            cardio_trace_clinic_id=env("CARDIO_TRACE_CLINIC_ID"),
            patient_role_id=env("PATIENT_ROLE_ID"),
            doctor_role_id=env("DOCTOR_ROLE_ID"),
            api_explorer_client_id=env("API_EXPLORER_CLIENT_ID"),
            api_explorer_client_secret=env("API_EXPLORER_CLIENT_SECRET"),
            auth0_client_id=env("AUTH0_CLIENT_ID"),
            cardio_trace_application_login_uri=env("CARDIO_TRACE_APPLICATION_LOGIN_URI"),
            invite_url_replacement=env("INVITE_URL_REPLACEMENT"),
        )


@dataclass(frozen=True)
class RouterSettings:
    """
    Settings for the gateway's HTTP-facing behaviour and upstream locations.
    """

    inner_api_base_url: str
    hasura_graphql_url: str

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "RouterSettings":
        env = Env(environ)
        return cls(
            inner_api_base_url=env("INNER_API_BASE_URL"),
            hasura_graphql_url=env("HASURA_GRAPHQL_URL"),
        )


@dataclass(frozen=True)
class JwtSettings:
    """
    Settings for JWT validation (`GatewayJwt`).
    """

    domain: str
    audience: str
    issuer: str

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "JwtSettings":
        env = Env(environ)
        return cls(
            domain=env("AUTH0_DOMAIN"),
            audience=env("AUTH0_AUDIENCE"),
            issuer=env("AUTH0_ISSUER"),
        )


@dataclass(frozen=True)
class RbacSettings:
    """
    Settings for edge RBAC enforcement (`RbacEnforcer`).
    """

    enforcement_mode: str
    model_path: str | None = None
    policy_path: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "RbacSettings":
        env = Env(environ)
        return cls(
            enforcement_mode=env("RBAC_ENFORCEMENT_MODE", required=False) or "audit",
            model_path=env("RBAC_MODEL_PATH", required=False),
            policy_path=env("RBAC_POLICY_PATH", required=False),
        )


@dataclass(frozen=True)
class AppSettings:
    """
    Aggregate of all gateway settings.

    """

    auth: AuthSettings
    invites: InviteSettings
    router: RouterSettings
    jwt: JwtSettings
    rbac: RbacSettings

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "AppSettings":
        auth = AuthSettings.from_env(environ)
        router = RouterSettings.from_env(environ)
        invites = InviteSettings.from_env(environ)
        jwt = JwtSettings.from_env(environ)
        rbac = RbacSettings.from_env(environ)
        return cls(
            auth=auth,
            invites=invites,
            router=router,
            jwt=jwt,
            rbac=rbac,
        )
