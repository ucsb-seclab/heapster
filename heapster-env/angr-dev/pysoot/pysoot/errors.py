
class PySootError(Exception):
    pass


class ParameterError(PySootError):
    pass


class JythonClientException(PySootError):
    pass


class RecvException(PySootError):
    pass

