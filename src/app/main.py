from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import Config
from app.error_handlers import (
    auth_service_exception_handler,
    csrf_validation_error_handler,
    invite_exception_handler,
    jwt_validation_error_handler,
)
from app.exceptions import CsrfValidationError, AuthServiceException, InviteException, JwtValidationError
from app.gateway import Gateway
from app.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not Config.INNER_AUTH_SERVICE_URL or not Config.HASURA_GRAPHQL_URL:
        raise RuntimeError(
            "INNER_AUTH_SERVICE_URL and HASURA_GRAPHQL_URL must be set in the environment."
        )
    if not Config.AUTH0_DOMAIN or not Config.AUTH0_AUDIENCE:
        raise RuntimeError(
            "AUTH0_DOMAIN and AUTH0_AUDIENCE must be set for session and JWT validation."
        )
    async with Gateway() as gateway:
        app.state.gateway = gateway
        yield


app = FastAPI(lifespan=lifespan)
app.add_exception_handler(JwtValidationError, jwt_validation_error_handler)
app.add_exception_handler(AuthServiceException, auth_service_exception_handler)
app.add_exception_handler(InviteException, invite_exception_handler)
app.add_exception_handler(CsrfValidationError, csrf_validation_error_handler)
app.include_router(router)
