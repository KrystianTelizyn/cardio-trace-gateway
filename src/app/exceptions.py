class AuthServiceException(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class InviteException(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class JwtValidationError(Exception):
    """Raised when an access token fails cryptographic or claim checks."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class CsrfValidationError(Exception):
    """Raised when CSRF validation fails for a browser-initiated request."""

    def __init__(self, message: str = "CSRF validation failed"):
        self.message = message
        super().__init__(self.message)