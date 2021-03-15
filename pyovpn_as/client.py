"""Provides functions to fetch AccessServerClient from multiple different
   credential sources, e.g. environment variables or a file
"""
import urllib.parse

from .api import exceptions

def validate_endpoint(url: str) -> bool:
    """Validates that a given URL is a (syntactically) valid endpoint URI for
       an AccessServer XML-RPC interface

    A valid endpoint would be a URL with no username and password (as in this
    module we construct these in the header rather than the URL), a https
    scheme, and no parameters or fragments. Very simply,
    https://hostname[:port]/path/

    Args:
        url (str): URL to validate

    Returns:
        bool: True if valid, False if not
    """
    parsed = urllib.parse.urlparse(url)
    # Verify https
    if parsed.scheme != 'https':
        return False
    # Verify no username or password
    elif parsed.username is not None or parsed.password is not None:
        return False
    # Verify hostname exists
    elif parsed.hostname is None or len(parsed.hostname) == 0:
        return False
    # Verify no params or fragments
    elif parsed.params != '' \
        or parsed.fragment != '' \
        or parsed.query != '':
        return False
    # Verify port is valid
    try:
        parsed.port
    except ValueError:
        return False
    else:
        return True


def validate_client_args(
    endpoint: str, username: str, password: str
) -> bool:
    """Validates that the endpoint, username, and password are all valid options
       to pass to the AccessServerClient class

    Args:
        endpoint (str): Endpoint the client will connect to
        username (str): Username which must not be blank or None and must be a
            string
        password (str): Password which must not be blank or contain the :
            character
    """
    # Endpoint
    if endpoint is None:
        raise exceptions.ApiClientConfigurationError(
            'Endpoint URL has not been set, cannot create client'
        )
    elif not isinstance(endpoint, str):
        raise exceptions.ApiClientConfigurationError(
            'Endpoint URL is not a string, cannot create client'
        )
    elif not validate_endpoint(endpoint):
        raise exceptions.ApiClientConfigurationError(
            'Endpoint URL is invalid as an endpoint URI.\n'
            'Endpoints must be https, must not contain usernames, passwords, '
            'param strings, or fragments, and must have either no port or a'
            'valid port.'
        )
    
    # Username
    elif username is None:
        raise exceptions.ApiClientConfigurationError(
            'Username is not set, cannot create client'
        )
    elif not isinstance(username, str):
        raise exceptions.ApiClientConfigurationError(
            'Username is not a string, cannot create client'
        )
    elif ':' in username:
        raise exceptions.ApiClientConfigurationError(
            'Username contains ":" character (illegal in basic auth), '
            'cannot create client'
        )
    
    # Password
    elif password is None:
        raise exceptions.ApiClientConfigurationError(
            'Password is not set, cannot create client'
        )
    elif not isinstance(password, str):
        raise exceptions.ApiClientConfigurationError(
            'Password is not a string, cannot create client'
        )
    elif ':' in password:
        raise exceptions.ApiClientConfigurationError(
            'Password contains ":" character (illegal in basic auth), '
            'cannot create client'
        )
    else:
        return True
