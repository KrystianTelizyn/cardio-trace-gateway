import json
import os
from urllib.parse import parse_qs, quote, urlparse
from uuid import uuid4

import pytest

@pytest.mark.integration
def test_playwright_auth0_login_happy_path(page, gateway_base_url):
    email = os.getenv("INTEGRATION_AUTH0_EMAIL").strip()
    password = os.getenv("INTEGRATION_AUTH0_PASSWORD").strip()
    organization_name = os.getenv("INTEGRATION_AUTH0_ORGANIZATION_NAME").strip()

    return_to = quote(f"/playwright-next-{uuid4().hex[:8]}", safe='')   
    login_response = page.goto(f"{gateway_base_url}/url/auth0?return_to={return_to}")
    assert login_response.status == 200
    login_url = login_response.json()["login_url"]

    
    page.goto(login_url)
    org_input = page.get_by_label("Organization name")
    org_input.first.fill(organization_name)
    page.get_by_role("button", name="Continue").click()

    email_input = page.get_by_label("Email")
    email_input.first.fill(email)

    password_input = page.locator("input[type='password']")
    password_input.first.fill(password)

    continue_button = page.get_by_role("button", name="Continue")
    continue_button.first.click()

    FRONTEND_URL = os.getenv("FRONTEND_URL").strip()
    AUTH_CALLBACK_SUCCESS_PATH = os.getenv("AUTH_CALLBACK_SUCCESS_PATH").strip()
    redirect_url = f"{FRONTEND_URL}{AUTH_CALLBACK_SUCCESS_PATH}?next={return_to}"
    page.wait_for_url(redirect_url, timeout=10000)

    me_response = page.goto(gateway_base_url + "/me")
    assert me_response.status == 200
    me_payload = me_response.json()
    assert me_payload.get("email") == email
    assert "doctor" in me_payload.get("roles", [])
