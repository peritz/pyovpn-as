"""Provides functions to fetch AccessServerClient from multiple different
   credential sources, e.g. environment variables or a file
"""
import json
import logging
import os
import urllib.parse

from . import utils
from .api import cli
from .api import exceptions


logger = logging.getLogger(__name__)


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


@utils.debug_log_call()
def from_env() -> cli.AccessServerClient:
    """Gets parameters for Access Server from environment variables

    The environment variables we are looking for here are:

    * `PYOVPN_AS_ENDPOINT_URL` - The endpoint of the Access Server API
    * `PYOVPN_AS_USERNAME` - Username to authenticate
    * `PYOVPN_AS_PASSWORD` - Password to authenticate

    The below environment variables are optional, and may be set to either
    "true" or "false"
    
    * `PYOVPN_AS_DEBUG` - Are we in debug mode, defaults to false
    * `PYOVPN_AS_ALLOW_UNTRUSTED` - Allow untrusted/unverified SSL context from
        Access Server, defaults to false

    Raises:
        ApiClientConfigurationError: Environment variables were invalid in some 
            way

    Returns:
        cli.AccessServerClient: configured using the above values
    """
    endpoint = os.environ.get('PYOVPN_AS_ENDPOINT_URL')
    username = os.environ.get('PYOVPN_AS_USERNAME')
    password = os.environ.get('PYOVPN_AS_PASSWORD')
    
    validate_client_args(endpoint, username, password)

    debug_str = os.environ.get('PYOVPN_AS_DEBUG', 'false')
    allow_untrusted_str = os.environ.get('PYOVPN_AS_ALLOW_UNTRUSTED', 'false')

    if debug_str.lower() == 'true':
        debug = True
    elif debug_str.lower() == 'false':
        debug = False
    else:
        raise exceptions.ApiClientConfigurationError(
            'PYOVPN_AS_DEBUG must be either true or false'
        )

    if allow_untrusted_str.lower() == 'true':
        allow_untrusted = True
    elif allow_untrusted_str.lower() == 'false':
        allow_untrusted = False
    else:
        raise exceptions.ApiClientConfigurationError(
            'PYOVPN_AS_ALLOW_UNTRUSTED must be either true or false'
        )

    logging.info(
        f'Creating client with ({repr(endpoint)}, {repr(username)}, '
        f'REDACTED, {repr(debug)}, {repr(allow_untrusted)})'
    )
    return cli.AccessServerClient(
        endpoint, username, password,
        debug, allow_untrusted
    )


@utils.debug_log_call()
def from_file(filepath: os.PathLike) -> cli.AccessServerClient:
    """Retrieve client configuration from file

    The file must be a JSON file with a single object, specifying the following:
        endpoint_url (str): The endpoint of the AS RPC API (https://<ip>/RPC2)
        username (str): Username to authenticate as
        password (str): Password for the above
        debug (bool, optional): Whether to provide debug information, default
            is false
        allow_untrusted (bool, optional): Whether to allow unverified SSL certs
            from server, default is false, should be turned off in production

    Args:
        filepath (os.PathLike): JSON file for configuration

    Raises:
        ApiClientConfigurationError: JSON configuration was invalid in some way

    Returns:
        cli.AccessServerClient: The client configured using the above options
    """
    with open(filepath) as config_file:
        config = json.loads(config_file.read())
    
    endpoint = config.get('endpoint_url')
    username = config.get('username')
    password = config.get('password')

    validate_client_args(endpoint, username, password)

    debug = config.get('debug', False)
    allow_untrusted = config.get('allow_untrusted', False)

    if not isinstance(debug, bool) or not isinstance(allow_untrusted, bool):
        raise exceptions.ApiClientConfigurationError(
            'debug and allow_untrusted must be either true or false'
        )
    
    logging.info(
        f'Creating client with ({repr(endpoint)}, {repr(username)}, '
        f'REDACTED, {repr(debug)}, {repr(allow_untrusted)})'
    )
    return cli.AccessServerClient(
        endpoint, username, password, debug, allow_untrusted
    )


@utils.debug_log_call(redact=[2, 'password'])
def from_args(
    endpoint: str,
    username: str,
    password: str,
    debug: bool=False,
    allow_untrusted: bool=False
) -> cli.AccessServerClient:
    """Connect to AccessServer using config specified in arguments

    Args:
        endpoint (str): Endpoint URL of the Access Server
            (https://hostname/RPC2/)
        username (str): Username to authenticate as
        password (str): Password to authenticate with
        debug (bool, optional): Log debug information. Defaults to False.
        allow_untrusted (bool, optional): Allow unverified SSL context and
            untrusted SSL certs from server. Defaults to False.

    Returns:
        cli.AccessServerClient
    """
    validate_client_args(endpoint, username, password)
    if not isinstance(debug, bool) or not isinstance(allow_untrusted, bool):
        raise exceptions.ApiClientConfigurationError(
            'debug and allow_untrusted must be either true or false'
        )
    logging.info(
        f'Creating client with ({repr(endpoint)}, {repr(username)}, '
        f'REDACTED, {repr(debug)}, {repr(allow_untrusted)})'
    )
    return cli.AccessServerClient(
        endpoint, username, password, debug, allow_untrusted
    )