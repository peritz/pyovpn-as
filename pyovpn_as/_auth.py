"""This module provides functionality to manage users, their permissions,
   their connection configs, etc
"""
import logging
from typing import Any

from pyovpn_as.api.cli import AccessServerClient
from pyovpn_as.api.exceptions import ApiClientBaseException

from . import _exceptions
from . import utils


logger = logging.getLogger(__name__)

@utils.debug_log_call
def get_user(
    client: AccessServerClient, username: str
) -> dict[str, Any]:
    """Retrieves a user from the server using the specified client

    Args:
        client (AccessServerClient): The client to interface with
        username (str): The user to fetch

    Raises:
        AccessServerProfileNotFoundError: Profile does not exist
        AccessServerProfileExistsError: Username provided is the name of a
            group, not a user

    Returns:
        dict[str, Any]: A dictionary representing the fetched user
    """
    user_dict = client.UserPropGet(pfilt=[username,])
    profile = user_dict.get(username)
    if profile is None:
        raise _exceptions.AccessServerProfileNotFoundError(
            f'Could not find profile for "{username}"'
        )
    elif profile.get('type') == 'group':
        raise _exceptions.AccessServerProfileExistsError(
            f'"{username}" is the name of a group, not a user'
        )
    else:
        return profile


@utils.debug_log_call
def create_new_user(
    client: AccessServerClient,
    username: str,
    password: str=None,
    group: str=None,
    generate_client: bool=True,
    prop_superuser: bool=None,
    prop_autologin: bool=None,
    prop_deny: bool=None,
    prop_pwd_change: bool=None,
    prop_pwd_strength: bool=None,
    prop_autogenerate: bool=None
) -> dict[str, Any]:
    """Creates a user with the given parameters

    This function will check if the given user exists, and if not will create it
    via a call to UserPropPut. Then, for every additional parameter set, we will
    make another call to UserPropPut, deleting the user if any errors occur in
    the process.

    Args:
        client (AccessServerClient): Client used to connect to Access Server
        username (str): Username of the user to create
        password (str, optional): Password to set for user. If None, no
            password will be set. Must adhere to complexity requirements.
            Defaults to None.
        group (str, optional): A default group to assign the user to. If set,
            this user will inherit all options that apply to the given group.
            Will raise an error if group does not exist. Defaults to None.
        generate_client (bool, optional): Whether or not to generate a
            certificate and openvpn client configuration file for this user.
            Users cannot connect to the VPN unless this is set to true (or a
            cert is generated later for them). Defaults to True. 
        prop_superuser (bool, optional): Whether or not to explicitly make this
            user an administrator. Defaults to None.
        prop_autologin (bool, optional): Whether or not to explicitly allow this
            user to connect without a username and password. Defaults to None.
        prop_deny (bool, optional): Explicitly deny access to the user.
            Defaults to None.
        prop_pwd_change (bool, optional): Whether or not to
            explicitly allow the user to change their password using the WebUI.
            Defaults to None.
        prop_pwd_strength (bool, optional): Whether or not to
            explicitly check the complexity of this user's password when they
            try to change it in the WebUI. Defaults to None.
        prop_autogenerate (bool, optional): Whether or not to prevent the server
            from automatically regenerating user connection profiles (client
            records) when they don't exist (e.g. revoked) on the server.
            Defaults to None

    Raises:
        AccessServerProfileExistsError: username provided already exists as
            either a user or a group

    Returns:
        dict[str, Any]: A dictionary representing the user just created

    TODO Add parameter to hide profile in ui
    """
    # 1. Check for existence of user
    profile_dict = client.UserPropGet(pfilt=[username,])
    if profile_dict.get(username) is not None:
        raise _exceptions.AccessServerProfileExistsError(
            f'Profile for "{username}" already exists on the server'
        )
    logger.debug(f'Got user "{username}"')
    
    # 2. If there is a group specified, check that it exists
    if group is not None:
        if not isinstance(group, str):
            raise TypeError(
                f"Expected str for arg 'group', got {type(group)}"
            )
        profile_dict = client.UserPropGet(pfilt=[group,])
        if profile_dict.get(group) is None:
            raise _exceptions.AccessServerProfileNotFoundError(
                f'Group "{group}" does not exist'
            )
        if profile_dict.get(group).get('type') != 'group':
            raise _exceptions.AccessServerProfileExistsError(
                f'Profile "{group}" is not a group'
            )
        logger.debug(f'Got group "{group}"')

    # 3. Collect other parameters
    param_dict = {}
    params = [
        (p, vars()[p]) for p in (
        'prop_superuser',
        'prop_autologin',
        'prop_deny',
        'prop_pwd_change',
        'prop_pwd_strength',
        'prop_autogenerate'
    )]
    for p_name, p_val in params:
        if p_val is None:
            continue
        elif not isinstance(p_val, bool):
            raise TypeError(
                f"Expected bool for arg '{p_name}', got {type(p_val)}"
            )
        elif p_val:
            param_dict[p_name] = 'true'
        else:
            param_dict[p_name] = 'false'
    logger.debug(f'param_dict = {param_dict}')
    
    # 4. Try to create the user and delete profile if any step fails
    logger.info(f'Creating user "{username}"')
    try:
        for key, value in param_dict.items():
            logger.debug(f'Setting property "{key}" on profile "{username}"')
            client.UserPropPut(username, key, value)
        if password is not None:
            logger.debug(f'Setting password on profile "{username}"')
            client.SetLocalPassword(username, password, '')
        if generate_client:
            create_client_for_user(client, username)
    except (
        ApiClientBaseException,
        _exceptions.AccessServerClientExistsError
    ) as api_err:
        logger.error(
            f'Could not create profile "{username}", '
            'aborting and deleting profile...'
        )
        client.UserPropDelAll(username)
        raise _exceptions.AccessServerProfileCreateError(
            'Encountered an issue when setting properties on new user'
        ) from api_err
    else:
        logger.debug(f'Fetching created profile for return...')
        profile_dict = client.UserPropGet(pfilt=[username,])
        profile = profile_dict.get(username)
        assert profile is not None
        return profile


@utils.debug_log_call
def create_client_for_user(client: AccessServerClient, user: str) -> None:
    """Creates a new client record for a given user, or raises an error if one
       exists

    Args:
        client (AccessServerClient): Client used to connect to Access Server
        user (str): Username to generate the client for

    Raises:
        AccessServerClientExistsError: A client record for the given user
            already exists
    """
    # 1. Verify we are creating a client for an existing user
    get_user(client, user)

    # 2. Check if there is already an existing client
    existing_clients = client.EnumClients()
    if user in existing_clients:
        raise _exceptions.AccessServerClientExistsError(
            f'Client record already exists for "{user}"'
        )
    
    # 3. Create client config and validate it exists
    client.AutoGenerateOnBehalfOf(user)
    new_existing_clients = client.EnumClients()
    if user not in new_existing_clients:
        raise _exceptions.AccessServerClientCreateError(
            f'Creation of client record for "{user}" failed for an unknown'
            ' reason'
        )

@utils.debug_log_call
def delete_user(
    client: AccessServerClient,
    username: str
) -> None:
    """Deletes a user from the server

    Args:
        client (AccessServerClient): Client used to connect to AccessServer
        username (str): User to delete

    Raises:
        AccessServerProfileNotFoundError: User we are trying to delete does not
            exist
        AccessServerProfileExistsError: username supplied is name of group
            profile
    """
    # 1. Check that the user exists
    profile_dict = client.UserPropGet(pfilt=[username,])
    if profile_dict.get(username) is None:
        raise _exceptions.AccessServerProfileNotFoundError(
            f'User "{username}" does not exist'
        )
    elif profile_dict.get(username)['type'] == 'group':
        raise _exceptions.AccessServerProfileExistsError(
            f'Profile "{username}" is a group, not a user'
        )
    
    # 2. Delete the user
    client.UserPropDelAll(username)

    # 3. Check that the profile is deleted
    profile_dict = client.UserPropGet(pfilt=[username,])
    if profile_dict.get(username) is not None:
        raise _exceptions.AccessServerProfileDeleteError(
            f'Could not delete profile "{username}" for an unknown reason'
        )


@utils.debug_log_call
def get_user_login_ovpn_config(
    client: AccessServerClient,
    username: str
) -> str:
    """Fetches the .ovpn configuration for 

    Args:
        client (AccessServerClient): Client used to connect to AccessServer
        username (str): Username to fetch configuration for

    Raises:
        AccessServerProfileNotFoundError: User does not have a user/pass login
            connection profile configured or user does not exist.
        AccessServerProfileExistsError: Username provided is the name of a
            group, not a user

    Returns:
        str: The unified connection profile for the given user requiring an
            interactive login
    """
    # Validate user exists before fetching their config
    get_user(client, username)

    # Use Get1 to prevent config being created in case of not existing
    config = client.Get1(username)
    if config is None:
        raise _exceptions.AccessServerProfileNotFoundError(
            f'Connection profile for user "{username}" could not be found on '
            'the server.'
        )
    else:
        return config[1]


@utils.debug_log_call
def revoke_user_certificates(
    client: AccessServerClient,
    username: str
) -> None:
    """Revoke all certificates for the given user

    Args:
        client (AccessServerClient): Client used to connect to AccessServer
        username (str): User whose certificates we want to revoke

    Raises:
        AccessServerProfileNotFoundError: User does not have a user/pass login
            connection profile configured or user does not exist.
        AccessServerProfileExistsError: Username provided is the name of a
            group, not a user
    """
    # Validate user exists
    get_user(client, username)

    # Revoke all certs
    client.RevokeUser(username)