import base64
import json
import os
import subprocess
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from playwright.sync_api import Browser, Page


def _is_integration_enabled() -> bool:
    return os.getenv("RUN_INTEGRATION") == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _is_integration_enabled():
        return
    skip_integration = pytest.mark.skip(reason="Set RUN_INTEGRATION=1 to run integration tests.")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


def _required_env() -> dict[str, str]:
    keys = [
        "INTEGRATION_AUTH0_DOMAIN",
        "INTEGRATION_INNER_SERVICE_URL",
        "INTEGRATION_HASURA_URL",
        "INTEGRATION_EXAMPLE_ACCESS_TOKEN",
    ]
    values: dict[str, str] = {}
    missing: list[str] = []
    for key in keys:
        value = os.getenv(key, "").strip()
        if not value:
            missing.append(key)
        else:
            values[key] = value
    if missing:
        raise RuntimeError(f"Missing required integration environment variables: {', '.join(missing)}")
    return values


@pytest.fixture(scope="session")
def integration_env() -> dict[str, str]:
    if not _is_integration_enabled():
        pytest.skip("Integration tests disabled.")
    return _required_env()


@pytest.fixture(scope="session")
def gateway_base_url(integration_env: dict[str, str]) -> Generator[str, None, None]:
    configured = os.getenv("INTEGRATION_GATEWAY_BASE_URL", "").strip()
    if configured:
        yield configured.rstrip("/")
        return

    host = "localhost"
    port = 8000

    project_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    command = [
        "uv",
        "run",
        "uvicorn",
        "app.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    process = subprocess.Popen(  # noqa: S603
        command,
        cwd=str(project_root),
        env=env,
    )
    base_url = f"http://{host}:{port}"

    deadline = time.time() + 20
    started = False
    with httpx.Client(timeout=1.0, follow_redirects=False) as client:
        while time.time() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    "Gateway app failed to start for integration tests.\n"
                    "See terminal output above for details."
                )
            try:
                response = client.get(f"{base_url}/healthz")
                if response.status_code == 200:
                    started = True
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)

    if not started:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        raise RuntimeError("Timed out waiting for local gateway app startup.")

    try:
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture(scope="session")
def integration_client(gateway_base_url: str) -> Generator[httpx.Client, None, None]:
    with httpx.Client(base_url=gateway_base_url, follow_redirects=False, timeout=30.0) as client:
        yield client


CSRF_COOKIE_NAME = "gateway_csrf"


@dataclass(frozen=True)
class AuthSession:
    """Cookies of a logged-in browser session, ready to send with httpx."""

    cookie_header: str
    csrf_token: str

    def headers(self, *, csrf: bool = True) -> dict[str, str]:
        headers = {"Cookie": self.cookie_header, "Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf_token
        return headers


def _required(key: str) -> str:
    value = os.getenv(key, "").strip()
    if not value:
        pytest.skip(f"Set {key} to run browser-based Auth0 login.")
    return value


@pytest.fixture(scope="session")
def auth0_login() -> Callable[[Page, str, str], None]:
    """Drive the Auth0 Universal Login form: organization, then email and password."""

    def _login(page: Page, gateway_base_url: str, return_to: str) -> None:
        organization_name = _required("INTEGRATION_AUTH0_ORGANIZATION_NAME")
        email = _required("INTEGRATION_AUTH0_EMAIL")
        password = _required("INTEGRATION_AUTH0_PASSWORD")

        response = page.goto(f"{gateway_base_url}/auth/login-url?return_to={quote(return_to, safe='')}")
        assert response is not None and response.status == 200
        page.goto(response.json()["login_url"])

        page.get_by_label("Organization name").first.fill(organization_name)
        page.get_by_role("button", name="Continue").click()
        page.get_by_label("Email").first.fill(email)
        page.locator("input[type='password']").first.fill(password)
        page.get_by_role("button", name="Continue").first.click()

    return _login


@pytest.fixture(scope="session")
def auth_session(
    gateway_base_url: str,
    browser: Browser,
    auth0_login: Callable[[Page, str, str], None],
) -> AuthSession:
    """
    A real gateway session for authenticated e2e tests.

    Uses INTEGRATION_SESSION_COOKIE / INTEGRATION_CSRF_TOKEN when set (e.g. CI without a
    browser); otherwise logs in once through Auth0 with Playwright and reuses the cookies.
    """
    cookie = os.getenv("INTEGRATION_SESSION_COOKIE", "").strip()
    csrf = os.getenv("INTEGRATION_CSRF_TOKEN", "").strip()
    if cookie and csrf:
        return AuthSession(cookie_header=f"{cookie}; {CSRF_COOKIE_NAME}={csrf}", csrf_token=csrf)

    frontend_url = _required("FRONTEND_URL")
    success_path = _required("AUTH_CALLBACK_SUCCESS_PATH")
    context = browser.new_context()
    try:
        page = context.new_page()
        auth0_login(page, gateway_base_url, "/")
        page.wait_for_url(f"{frontend_url}{success_path}**", timeout=15000)
        cookies = {
            c.get("name", ""): c.get("value", "") for c in context.cookies(gateway_base_url)
        }
    finally:
        context.close()

    if CSRF_COOKIE_NAME not in cookies:
        raise RuntimeError("Login finished but the gateway did not set the gateway_csrf cookie.")
    return AuthSession(
        cookie_header="; ".join(f"{name}={value}" for name, value in cookies.items()),
        csrf_token=cookies[CSRF_COOKIE_NAME],
    )


@pytest.fixture(scope="session")
def decoded_access_token_payload(integration_env: dict[str, str]) -> dict[str, Any]:
    token = integration_env["INTEGRATION_EXAMPLE_ACCESS_TOKEN"]
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("INTEGRATION_EXAMPLE_ACCESS_TOKEN must be a JWT-like value.")
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    payload_raw = base64.urlsafe_b64decode(payload_b64 + padding)
    payload = json.loads(payload_raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Decoded JWT payload is not an object.")
    return payload


@pytest.fixture(scope="session")
def callback_query_string() -> str | None:
    # Optional, for pipelines able to pre-obtain Auth0 code/state.
    # Format: code=...&state=...
    qs = os.getenv("INTEGRATION_AUTH0_CALLBACK_QUERY", "").strip()
    return qs or None


@pytest.fixture(scope="session")
def integration_graphql_probe_query() -> str:
    return os.getenv("INTEGRATION_GRAPHQL_PROBE_QUERY", "{__typename}")


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, Any]) -> dict[str, Any]:
    slow_mo_ms = int(os.getenv("PLAYWRIGHT_SLOW_MO_MS", "250"))
    headless = os.getenv("PLAYWRIGHT_HEADLESS", "0") == "1"
    return {**browser_type_launch_args, "headless": headless, "slow_mo": slow_mo_ms}
