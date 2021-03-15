"""This module provides definitions for high level errors relating to the
   functions provided by the root modules in this package.
   
Errors relating to high level functions in the root modules of the pyovpn_as
package will not have a direct mapping at the API and XML-RPC level. Where the
API may deal with issues such as password complexity, authorisation, and
parameter validation, the exceptions defined here will deal with logical errors.

An example of this may be when we attempt to create a new user, but this user
already exists. The API will let us go ahead and overwrite the existing user's 
properties, but this does not make sense from our perspective, and could cause
substantial and confusing issues.

Similarly, if we attempt to add a user to a group, but that group doesn't exist
(e.g. we made a typo), we would generally want the program to tell us, as
indeed the Web Admin UI does, but the API would not tell us, and would happily
let us set the property without a second thought.
"""


class AccessServerBaseException(BaseException):
    """Base exception for all exceptions in this module
    """
    pass


class AccessServerProfileExistsError(AccessServerBaseException):
    """Raised when we try to create a user or group that already exists
    """
    pass


class AccessServerProfileNotFoundError(AccessServerBaseException):
    """Raised when we try to access a user or group that does not exist
    """
    pass


class AccessServerProfileCreateError(AccessServerBaseException):
    """Raised when an error is encountered when creating a new profile
    """