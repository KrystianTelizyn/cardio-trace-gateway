import pytest


@pytest.mark.integration
def test_decoded_token_payload_has_required_claims(decoded_access_token_payload):
    payload = decoded_access_token_payload
    for claim in ("sub", "aud", "iss", "exp"):
        assert claim in payload, f"Missing expected claim: {claim}"


@pytest.mark.integration
def test_decoded_token_audience_shape(decoded_access_token_payload):
    aud = decoded_access_token_payload["aud"]
    assert isinstance(aud, (str, list))
    if isinstance(aud, list):
        assert all(isinstance(item, str) for item in aud)
