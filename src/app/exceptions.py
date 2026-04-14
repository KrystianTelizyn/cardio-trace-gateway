class GatewayExceptionBase(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

class AuthServiceException(GatewayExceptionBase):
    pass


class AuthCallbackRedirectException(GatewayExceptionBase):
    """Raised when callback handling should redirect browser to frontend error route."""

    def __init__(self, code: str = "auth_callback_failed"):
        super().__init__("Authentication callback failed")
        self.code = code

class InviteException(GatewayExceptionBase):
    pass


class JwtValidationError(GatewayExceptionBase):
    """Raised when an access token fails cryptographic or claim checks."""
    pass


class CsrfValidationError(GatewayExceptionBase):
    """Raised when CSRF validation fails for a browser-initiated request."""

class ConfigError(GatewayExceptionBase):
    """Raised when required configuration is missing or invalid."""
    pass


class InviteRegistrationError(GatewayExceptionBase):
    """Raised when notifying the inner API about a completed invite registration fails."""
    pass


class GatewayNotReadyError(GatewayExceptionBase):
    """Raised when gateway readiness checks fail."""

    def __init__(self, checks: dict[str, bool]):
        super().__init__("Gateway is not ready")
        self.checks = checks
