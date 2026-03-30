from typing import Self

from app.config import Config
from app.gateway.auth import GatewayAuth
from app.gateway.jwt import GatewayJwt
from app.gateway.router import GatewayRouter
from app.gateway.invites import Invites


class Gateway:
    def __init__(self) -> None:
        self.auth = GatewayAuth()
        self.jwt = GatewayJwt()
        self.invites = Invites()
        self.router = GatewayRouter(
            inner_api_base=Config.INNER_AUTH_SERVICE_URL,
            hasura_graphql_url=Config.HASURA_GRAPHQL_URL,
        )

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