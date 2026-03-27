class AuthServiceException(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class InviteException(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)