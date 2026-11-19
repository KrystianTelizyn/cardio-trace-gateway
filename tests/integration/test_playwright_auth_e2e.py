import os
from urllib.parse import quote
from uuid import uuid4

import pytest


@pytest.mark.integration
def test_playwright_auth0_login_happy_path(page, gateway_base_url, auth0_login):
    frontend_url = os.getenv("FRONTEND_URL", "").strip()
    success_path = os.getenv("AUTH_CALLBACK_SUCCESS_PATH", "").strip()
    email = os.getenv("INTEGRATION_AUTH0_EMAIL", "").strip()
    if not (frontend_url and success_path and email):
        pytest.skip("Set FRONTEND_URL, AUTH_CALLBACK_SUCCESS_PATH and INTEGRATION_AUTH0_EMAIL.")

    return_to = f"/playwright-next-{uuid4().hex[:8]}"
    auth0_login(page, gateway_base_url, return_to)

    # The callback lands on the frontend success page and carries return_to as `next`.
    page.wait_for_url(
        f"{frontend_url}{success_path}?next={quote(return_to, safe='')}", timeout=15000
    )

    me_response = page.goto(gateway_base_url + "/auth/me")
    assert me_response is not None and me_response.status == 200
    me_payload = me_response.json()
    assert me_payload.get("email") == email
    assert "doctor" in me_payload.get("roles", [])
