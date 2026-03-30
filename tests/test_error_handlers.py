import pytest

from app.error_handlers import (
    auth_service_exception_handler,
    csrf_validation_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import (
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
async def test_invite_exception_handler_maps_502():
    response = await invite_exception_handler(None, InviteException("invite failed"))
    assert response.status_code == 502
    assert response.body == b'{"detail":"invite failed"}'


@pytest.mark.asyncio
async def test_csrf_validation_error_handler_maps_403():
    response = await csrf_validation_error_handler(None, CsrfValidationError("csrf bad"))
    assert response.status_code == 403
    assert response.body == b'{"detail":"csrf bad"}'
