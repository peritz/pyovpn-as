"""This module provides functionality to manage users, their permissions,
   their connection configs, etc
"""
import logging
from typing import Any

from pyovpn_as.api.cli import AccessServerClient
from . import _exceptions


logger = logging.getLogger(__name__)

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
    logger.debug(f'get_user() called ({client}, {username})')
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
