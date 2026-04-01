from contextlib import asynccontextmanager

from fastapi import FastAPI
from dotenv import load_dotenv

from app.config import AppSettings
from app.error_handlers import (
    auth_service_exception_handler,
    csrf_validation_error_handler,
    gateway_not_ready_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import (
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


app = FastAPI(lifespan=lifespan)
app.add_exception_handler(JwtValidationError, jwt_validation_error_handler)
app.add_exception_handler(AuthServiceException, auth_service_exception_handler)
app.add_exception_handler(InviteException, invite_exception_handler)
app.add_exception_handler(CsrfValidationError, csrf_validation_error_handler)
app.add_exception_handler(GatewayNotReadyError, gateway_not_ready_error_handler)
app.include_router(router)
