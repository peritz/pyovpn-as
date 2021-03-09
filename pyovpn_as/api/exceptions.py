"""A module containing possible exceptions that may arise during communication
   with the XML-RPC endpoint for Access Server
"""
import xmlrpc.client

class AccessServerBaseException(BaseException):
    """Used as a base exception for other errors in the API conversation
       that are not XMLRPC Faults, e.g. bad password in SetLocalPassword
    """
    pass

class AccessServerAuthError(AccessServerBaseException):
    """Given by Fault Code 9007, this error pertains to the user either not 
       having correct permissions or their login being incorrect.
    """
    pass

class AccessServerParameterError(AccessServerBaseException):
    """Given by Fault Code 8002, this error indicates that the number of 
       parameters passed to the given method is incorrect
    """
    pass

class AccessServerValueError(AccessServerBaseException):
    """The Fault Code for this exception will be 9000, but the Fault String
       will begin with something like 'XMLRPCRelay: exceptions.ValueError:'
    """
    pass

class AccessServerInternalError(AccessServerBaseException):
    """Raised when the Fault Code is 9000 and Fault String is "XMLRPC: 
       internal error"
    """
    pass

# -----------------
# ---- Methods ----
# -----------------
def translate_fault(err: Exception) -> None:
        """Translates a given exception into one more friendly for the user

        We return the exception rather than raise it because no error has
        occurred in this method. We return so that it can be raised in the right
        place to prevent confusion.

        Args:
            err (Exception): The Exception to translate

        Returns:
            Exception: this time it's the correct type with message and all
        """
        if not isinstance(err, xmlrpc.client.Fault):
            return err
        elif err.faultCode == 8002:
            return AccessServerParameterError(
                'Number of parameters is incorrect'
            )
        elif err.faultCode == 9007:
            return AccessServerAuthError(
                'Either your credentials are wrong or your permissions are not'
                ' correct to run the given method.'
            )
        elif err.faultCode == 9000 and err.faultString.startswith(
            'XMLRPCRelay: exceptions.ValueError: '
        ):
            start_from = len('XMLRPCRelay: exceptions.ValueError: ')
            return AccessServerValueError(
                f'ValueError from server: {err.faultString[start_from:]}'
            )
        elif err.faultCode == 9000 and \
            err.faultString == 'XMLRPC: internal error':
            return AccessServerInternalError(
                'Something unknown went wrong with that call that the server '
                'did not like'
            )

