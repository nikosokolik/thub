class TapException(Exception):
    pass


class TapError(Exception):
    pass


class TapExistsError(TapError):
    pass


class InvalidTapNameError(TapError):
    pass


class TapRawSocketException(TapException):
    pass
