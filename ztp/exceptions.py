from enum import Enum


class _AutoNumber(Enum):
    def __new__(cls):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        return obj


class ErrorCode(_AutoNumber):
    # Invalid data
    INVALID_DATA = ()
    NO_CONFIG_PROVIDED = ()
    INVALID_CERTIFICATE = ()
    INVALID_SERIAL_NUM = ()
    FILE_NOT_FOUND = ()
    X509_VERIFICATION_FAILED = ()

    DATA_SIGNING_FAILED = ()
    DATA_ENCRYPTION_FAILED = ()
    DATA_ENCODING_FAILED = ()

    SIGNATURE_VERIFICATION_ON_DATA_FAILED = ()
    DATA_DECRYPTION_FAILED = ()
    DATA_DECODING_FAILED = ()

    # TODO: Find a better name
    CMS_DATA_CREATION_FAILED = ()
    CMS_DATA_EXTRACTION_FAILED = ()

    def __str__(self):
        return str(self.name).lower().replace('_', '-')

    def __repr__(self):
        return str(self)


class Error(Exception):
    def __init__(self, errorCode=None, error=None):
        self.errorCode = errorCode
        self.error = error
        message = str(self.errorCode) if errorCode else None
        super(Exception, self).__init__(message)

    def __str__(self):
        message = 'Error: {}'.format(str(self.errorCode))
        if self.error:
            message += '. Reason: {}'.format(str(self.error))

        return message

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False


class CryptoError(Error):
    pass


class DecodeError(Error):
    pass


class ExecError(Exception):
    def __init__(self, cmd, error):
        self.cmd = cmd
        self.error = error
        super(ExecError, self).__init__(self.error)
