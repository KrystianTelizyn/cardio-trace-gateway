from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.types import Lifespan
from dotenv import load_dotenv

from app.config import AppSettings
from auth0_server_python.error import AccessTokenError

from app.error_handlers import (
    access_token_error_handler,
    auth_callback_redirect_exception_handler,
    auth_service_exception_handler,
    csrf_validation_error_handler,
    gateway_not_ready_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import (
    AuthCallbackRedirectException,
    CsrfValidationError,
    AuthServiceException,
    GatewayNotReadyError,
    InviteException,
    JwtValidationError,
)
from app.gateway import Gateway
from app.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_dotenv()
    settings = AppSettings.from_env()
    async with Gateway(settings) as gateway:
        app.state.gateway = gateway
        yield

def create_app(*, lifespan: Lifespan[FastAPI] | None = None):
    app = FastAPI(lifespan=lifespan)
    app.add_exception_handler(JwtValidationError, jwt_validation_error_handler)
    app.add_exception_handler(AccessTokenError, access_token_error_handler)
    app.add_exception_handler(AuthCallbackRedirectException, auth_callback_redirect_exception_handler)
    app.add_exception_handler(AuthServiceException, auth_service_exception_handler)
    app.add_exception_handler(InviteException, invite_exception_handler)
    app.add_exception_handler(CsrfValidationError, csrf_validation_error_handler)
    app.add_exception_handler(GatewayNotReadyError, gateway_not_ready_error_handler)

    app.include_router(router)
    return app

app = create_app(lifespan=lifespan)