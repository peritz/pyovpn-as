"""A module containing possible exceptions that may arise during communication
   with the XML-RPC endpoint for Access Server
"""
class AccessServerAuthError(BaseException):
    """Given by Fault Code 9007, this error pertains to the user either not 
       having correct permissions or their login being incorrect.
    """
    pass

class AccessServerParameterError(BaseException):
    """Given by Fault Code 8002, this error indicates that the number of 
       parameters passed to the given method is incorrect
    """
    pass

class AccessServerValueError(ValueError):
    """The Fault Code for this exception will be 9000, but the Fault String
       will begin with something like 'XMLRPCRelay: exceptions.ValueError:'
    """
    pass

class AccessServerInternalError(BaseException):
    """Raised when the Fault Code is 9000 and Fault String is "XMLRPC: 
       internal error"
    """
    pass

class AccessServerBaseException(BaseException):
    """Used as a base exception for other errors in the API conversation
       that are not XMLRPC Faults, e.g. bad password in SetLocalPassword
    """
    pass
