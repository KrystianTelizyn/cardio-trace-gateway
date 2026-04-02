from types import SimpleNamespace

import pytest

from app.error_handlers import (
    auth_callback_redirect_exception_handler,
    auth_service_exception_handler,
    csrf_validation_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import (
    AuthCallbackRedirectException,
    AuthServiceException,
    CsrfValidationError,
    InviteException,
    JwtValidationError,
)


@pytest.mark.asyncio
async def test_jwt_validation_error_handler_maps_401():
    response = await jwt_validation_error_handler(None, JwtValidationError("bad"))
    assert response.status_code == 401
    assert response.body == b'{"detail":"Invalid or expired access token"}'


@pytest.mark.asyncio
async def test_auth_service_exception_handler_maps_502():
    response = await auth_service_exception_handler(None, AuthServiceException("auth0 failed"))
    assert response.status_code == 502
    assert response.body == b'{"detail":"auth0 failed"}'


@pytest.mark.asyncio
async def test_auth_callback_redirect_exception_handler_maps_302_to_frontend():
    fake_gateway = SimpleNamespace(
        auth=SimpleNamespace(
            error_redirect_url=lambda code: (
                f"https://frontend.example.com/auth/callback/error?code={code}"
            )
        )
    )
    fake_request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(gateway=fake_gateway)))

    response = await auth_callback_redirect_exception_handler(
        fake_request, AuthCallbackRedirectException("auth_callback_failed")
    )
    assert response.status_code == 302
    assert response.headers["location"] == (
        "https://frontend.example.com/auth/callback/error?code=auth_callback_failed"
    )


@pytest.mark.asyncio
async def test_invite_exception_handler_maps_502():
    response = await invite_exception_handler(None, InviteException("invite failed"))
    assert response.status_code == 502
    assert response.body == b'{"detail":"invite failed"}'


@pytest.mark.asyncio
async def test_csrf_validation_error_handler_maps_403():
    response = await csrf_validation_error_handler(None, CsrfValidationError("csrf bad"))
    assert response.status_code == 403
    assert response.body == b'{"detail":"csrf bad"}'
