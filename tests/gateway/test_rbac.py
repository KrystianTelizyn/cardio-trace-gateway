from pathlib import Path

import pytest

from app.config import RbacSettings
from app.exceptions import RbacDeniedError
from app.gateway.rbac import RbacEnforcer


def test_settings_constructor_uses_default_policy_files() -> None:
    enforcer = RbacEnforcer(RbacSettings(enforcement_mode="enforce"))
    enforcer.check_rest("GET", "patients/123", "doctor")


def test_settings_constructor_honors_custom_file_paths(tmp_path: Path) -> None:
    model_path = tmp_path / "model.conf"
    policy_path = tmp_path / "policy.csv"
    model_path.write_text(
        "\n".join(
            [
                "[request_definition]",
                "r = role, method, path",
                "",
                "[policy_definition]",
                "p = role, method, path",
                "",
                "[policy_effect]",
                "e = some(where (p.eft == allow))",
                "",
                "[matchers]",
                "m = r.role == p.role && r.method == p.method && keyMatch2(r.path, p.path)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    policy_path.write_text("p, patient, GET, /self\n", encoding="utf-8")

    enforcer = RbacEnforcer(
        RbacSettings(
            enforcement_mode="enforce",
            model_path=str(model_path),
            policy_path=str(policy_path),
        )
    )
    enforcer.check_rest("GET", "self", "patient")
    with pytest.raises(RbacDeniedError):
        enforcer.check_rest("POST", "self", "patient")


def test_from_strings_constructor_allows_in_memory_policies() -> None:
    enforcer = RbacEnforcer.from_strings(
        model_text="""
[request_definition]
r = role, method, path

[policy_definition]
p = role, method, path

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.role == p.role && r.method == p.method && keyMatch2(r.path, p.path)
""",
        policy_text="p, doctor, GET, /alpha/*\n",
        mode="enforce",
    )
    enforcer.check_rest("GET", "alpha/1", "doctor")
    with pytest.raises(RbacDeniedError):
        enforcer.check_rest("GET", "beta/1", "doctor")


def test_method_and_role_mismatch_are_denied() -> None:
    enforcer = RbacEnforcer(RbacSettings(enforcement_mode="enforce"))
    with pytest.raises(RbacDeniedError):
        enforcer.check_rest("POST", "patients/123", "patient")


def test_unknown_path_is_default_deny() -> None:
    enforcer = RbacEnforcer(RbacSettings(enforcement_mode="enforce"))
    with pytest.raises(RbacDeniedError):
        enforcer.check_rest("GET", "unknown/thing", "doctor")


def test_graphql_role_checks() -> None:
    enforcer = RbacEnforcer(RbacSettings(enforcement_mode="enforce"))
    enforcer.check_graphql("POST", "doctor")
    enforcer.check_graphql("POST", "patient")
    with pytest.raises(RbacDeniedError):
        enforcer.check_graphql("POST", "stranger")


def test_audit_mode_logs_and_allows(caplog: pytest.LogCaptureFixture) -> None:
    enforcer = RbacEnforcer(RbacSettings(enforcement_mode="audit"))
    with caplog.at_level("WARNING"):
        enforcer.check_rest("DELETE", "alerts/1", "patient")
    assert "rbac_violation" in caplog.text
