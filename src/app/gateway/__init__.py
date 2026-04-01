from typing import Self

from app.config import AppSettings
from app.exceptions import GatewayNotReadyError
from app.gateway.auth import GatewayAuth
from app.gateway.jwt import GatewayJwt
from app.gateway.router import GatewayRouter
from app.gateway.invites import Invites


class Gateway:
    def __init__(self, settings: AppSettings) -> None:
        """
        Aggregate gateway facade wired with explicit settings.

        The application should construct AppSettings.from_env() once at startup
        and pass it here.
        """
        self.settings = settings
        self.auth = GatewayAuth(settings.auth)
        self.jwt = GatewayJwt(settings.jwt)
        self.invites = Invites(settings.invites)
        self.router = GatewayRouter(settings.router)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: object | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self.router.aclose()

    def readiness_checks(self) -> dict[str, bool]:
        return {
            "gateway": True,
            "auth": hasattr(self, "auth"),
            "jwt": hasattr(self, "jwt"),
            "router": hasattr(self, "router"),
            "invites": hasattr(self, "invites"),
        }

    def ensure_ready(self) -> dict[str, bool]:
        checks = self.readiness_checks()
        if not all(checks.values()):
            raise GatewayNotReadyError(checks=checks)
        return checks