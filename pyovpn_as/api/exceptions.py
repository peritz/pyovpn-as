"""A module containing possible exceptions that may arise during communication
   with the XML-RPC endpoint for Access Server
"""
import xmlrpc.client

class ApiClientBaseException(Exception):
    """Used as a base exception for other errors in the API conversation
       that are not XMLRPC Faults, e.g. bad password in SetLocalPassword
    """
    pass

class ApiClientPasswordComplexityError(ApiClientBaseException):
    """Raised when the new password sent to the server during a password change
       does not meet the complexity requirements set by the server.

    Generally speaking, the Access Server requires passwords to be at least 8
    characters long, contain an uppercase letter, a lowercase letter, a digit
    and a symbol from !@#$%&'()*+,-/[\\]^_`{|}~<>. (full stop included, also
    note the absence of colon and double quotation marks).
    """
    pass

class ApiClientPasswordIncorrectError(ApiClientBaseException):
    """Raised when the current password sent to the server during a password
       password change method call (e.g. SetLocalPassword) is incorrect
    """
    pass

class ApiClientPasswordResetError(ApiClientBaseException):
    """Raised when something goes wrong that was not expected during a password
       change method call (e.g. SetLocalPassword)
    """
    pass

class ApiClientUnexpectedError(ApiClientBaseException):
    """Raised when an error occurs that we hadn't accounted for. If this is
       raised we should review the error closely and create a new exception
       class for it
    """
    pass

class ApiClientConfigurationError(ApiClientBaseException):
    """Raised when the configuration we have attempted to use for creating an
       AccessServerClient is invalid, e.g. no endpoint configured
    """
    pass

