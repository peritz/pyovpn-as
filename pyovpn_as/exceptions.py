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


class AccessServerBaseException(Exception):
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
    pass


class AccessServerProfileDeleteError(AccessServerBaseException):
    """Raised when an unknown error is encountered when deleting a profile
    """
    pass


class AccessServerClientExistsError(AccessServerBaseException):
    """Raised when we try to create a client record that already exists
    """
    pass


class AccessServerClientCreateError(AccessServerBaseException):
    """Raised when an error is encountered when creating a new client record
    """
    pass


class PasswordGenerationComplexityTimeout(Exception):
    """Raised when we have been unable to generate a suitably complex password
    """
    pass


class AccessServerConfigError(AccessServerBaseException):
    """Raised when the configuration on the server does not permit a given
       operation to be run
    """
    pass


class AccessServerProfileIntegrityError(AccessServerBaseException):
    """Raised when a profile contains a value that wasn't expected. E.g. when the ``type`` property contains anything other than the defined types.
    """
    pass


class AccessServerPropOverwriteError(AccessServerProfileIntegrityError):
    """Raised when one attempts to overwrite a critical profile property that 
    already has a value on the server (e.g. trying to add a user to a group 
    when they are already a part of another group)
    """
    pass