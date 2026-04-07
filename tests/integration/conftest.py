import base64
import json
import os
import subprocess
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import httpx
import pytest


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
def gateway_base_url(integration_env: dict[str, str]) -> str:
    configured = os.getenv("INTEGRATION_GATEWAY_BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")

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


@pytest.fixture(scope="session")
def integration_session_cookie() -> str | None:
    # Provide this when callback automation is not available in CI.
    cookie = os.getenv("INTEGRATION_SESSION_COOKIE", "").strip()
    return cookie or None


@pytest.fixture(scope="session")
def integration_csrf_token() -> str | None:
    # Optional for unsafe-method proxy tests in CI/staging.
    token = os.getenv("INTEGRATION_CSRF_TOKEN", "").strip()
    return token or None


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
def integration_inner_probe_path() -> str:
    return os.getenv("INTEGRATION_INNER_PROBE_PATH", "health").strip("/")


@pytest.fixture(scope="session")
def integration_graphql_probe_query() -> str:
    return os.getenv("INTEGRATION_GRAPHQL_PROBE_QUERY", "{__typename}")


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, Any]) -> dict[str, Any]:
    slow_mo_ms = int(os.getenv("PLAYWRIGHT_SLOW_MO_MS", "250"))
    return {**browser_type_launch_args, "headless": False, "slow_mo": slow_mo_ms}
