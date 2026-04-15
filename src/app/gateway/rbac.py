from __future__ import annotations

import logging
from pathlib import Path

import casbin
from casbin.persist.adapters import StringAdapter

from app.config import RbacSettings
from app.exceptions import RbacDeniedError

_logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = _MODULE_DIR / "rbac_model.conf"
DEFAULT_POLICY_PATH = _MODULE_DIR / "rbac_policy.csv"
GRAPHQL_ALLOWED_ROLES = frozenset({"doctor", "patient"})


class RbacEnforcer:
    """Casbin-backed edge RBAC enforcer for proxy routes."""

    def __init__(self, settings: RbacSettings) -> None:
        model_path = Path(settings.model_path) if settings.model_path else DEFAULT_MODEL_PATH
        policy_path = Path(settings.policy_path) if settings.policy_path else DEFAULT_POLICY_PATH
        self._enforcer = casbin.Enforcer(str(model_path), str(policy_path))
        self._mode = settings.enforcement_mode

    @classmethod
    def from_strings(
        cls,
        *,
        model_text: str,
        policy_text: str,
        mode: str = "audit",
    ) -> RbacEnforcer:
        """Build an enforcer from in-memory model and policy strings (tests)."""
        model = casbin.Model()
        model.load_model_from_text(model_text)
        adapter = StringAdapter(policy_text)
        enforcer = casbin.Enforcer(model, adapter)

        instance = object.__new__(cls)
        instance._enforcer = enforcer
        instance._mode = mode
        return instance

    def check_rest(self, method: str, proxy_path: str, role: str) -> None:
        path = f"/{proxy_path.lstrip('/')}"
        allowed = self._enforcer.enforce(role, method.upper(), path)
        if allowed:
            return

        _logger.warning(
            "rbac_violation role=%s method=%s path=%s mode=%s",
            role,
            method,
            path,
            self._mode,
        )
        if self._mode == "enforce":
            raise RbacDeniedError(method=method, path=path, role=role)

    def check_graphql(self, method: str, role: str) -> None:
        if role in GRAPHQL_ALLOWED_ROLES:
            return

        _logger.warning(
            "rbac_violation role=%s method=%s path=/graphql mode=%s",
            role,
            method,
            self._mode,
        )
        if self._mode == "enforce":
            raise RbacDeniedError(method=method, path="/graphql", role=role)
