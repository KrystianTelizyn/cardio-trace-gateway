from fastapi import FastAPI
from app.routes import router
from contextlib import asynccontextmanager
from app.service import AuthService

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.auth_service = AuthService()
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(router)