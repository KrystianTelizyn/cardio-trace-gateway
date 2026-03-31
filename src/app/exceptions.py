class GatewayExceptionBase(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

class AuthServiceException(GatewayExceptionBase):
    pass

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
