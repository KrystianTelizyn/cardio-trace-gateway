from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

from app.config import AuthSettings


@dataclass(frozen=True)
class AuthRedirectPolicy:
    """
    URL/redirect policy for auth flows.

    Responsibilities:
    - Normalize `return_to` to prevent open redirects (same-origin enforcement).
    - Build callback success/error redirect URLs back to the frontend.
    - Decide whether the gateway CSRF cookie should be marked `Secure` based on
      the configured frontend scheme.
    """

    frontend_url: str
    callback_success_path: str
    callback_error_path: str
    default_return_to: str = "/"

    @classmethod
    def from_auth_settings(cls, settings: AuthSettings) -> "AuthRedirectPolicy":
        return cls(
            frontend_url=settings.frontend_url,
            callback_success_path=settings.callback_success_path,
            callback_error_path=settings.callback_error_path,
            default_return_to="/",
        )

    def normalize_return_to(self, return_to: str | None) -> str:
        """
        Enforce:
        - relative paths only (must start with `/`),
        - and, for absolute URLs, same-origin only.
        """
        if not return_to:
            return self.default_return_to

        parsed = urlparse(return_to)
        is_absolute = bool(parsed.scheme or parsed.netloc)
        if is_absolute:
            frontend_origin = self._frontend_origin()
            return_to_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
            if frontend_origin != return_to_origin:
                return self.default_return_to
            return (
                f"{parsed.path or self.default_return_to}"
                f'{"?" + parsed.query if parsed.query else ""}'
            )

        if return_to.startswith("//") or not return_to.startswith("/"):
            return self.default_return_to
        return return_to

    def build_callback_success_redirect_url(self, return_to: str | None) -> str:
        return self._build_frontend_redirect_url(
            self.callback_success_path,
            {"next": self.normalize_return_to(return_to)},
        )

    def build_callback_error_redirect_url(self, code: str = "auth_callback_failed") -> str:
        return self._build_frontend_redirect_url(
            self.callback_error_path,
            {"code": code},
        )

    def frontend_secure(self) -> bool:
        """
        Whether to mark the gateway CSRF cookie as `Secure`.

        Mirrors the existing behavior: treat `frontend_url` as authoritative;
        default to `False` when unset/empty.
        """
        frontend_url = self.frontend_url or ""
        if not frontend_url:
            return False
        return urlparse(frontend_url).scheme == "https"

    def _build_frontend_redirect_url(self, path: str, query_params: dict[str, str]) -> str:
        base = self.frontend_url.rstrip("/")
        query = urlencode(query_params)
        return f"{base}{path}?{query}"

    def _frontend_origin(self) -> str | None:
        parsed = urlparse(self.frontend_url or "")
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def build_frontend_absolute_url(self, path_with_query: str) -> str:
        """
        Join configured frontend base URL with a normalized path (and optional query).

        Used for Auth0 logout `returnTo`, which must be an absolute URL allowlisted in Auth0.
        """
        base = (self.frontend_url or "").rstrip("/")
        if not path_with_query.startswith("/"):
            path_with_query = f"/{path_with_query}"
        return f"{base}{path_with_query}"

