"""This module provides the UserOperations class which allows us to define
high-level functionality for managing users on the sacli server
"""

import hashlib
import logging
import json
from typing import Union
from dataclasses import dataclass, field, fields, asdict

import pyovpn_as.api.exceptions

from . import exceptions, utils
from .api import client
from .types import _User, _UserPropValue

logger = logging.getLogger(__name__)


class User:
    """Represents a user on the server"""

    def __init__(self, **kwargs):
        self._user = _User(**kwargs)
        self._updated = []  # List of keys that have been updated on _user

    def __getattr__(self, name):
        attr = getattr(self._user, name)
        if isinstance(attr, _UserPropValue):
            return attr.value
        return attr

    def __setattr__(self, name, value):
        """Use None to force the user to inherit the value from their group"""
        # We avoid calling getattr on attributes within __init__
        if name == "_user" or name == "_updated":
            super().__setattr__(name, value)
            return
        # If attr is a _UserPropValue then we want to override the inherited setting
        attr = getattr(self._user, name)
        if isinstance(attr, _UserPropValue):
            attr.value = value
            if attr.inherited:
                attr.inherited = False
        else:
            super().__setattr__(name, value)
        self._updated.append(name)

    def __delattr__(self, name):
        """Delete an attribute to force the user to inherit the value from their group"""
        attr = getattr(self._user, name)
        if isinstance(attr, _UserPropValue):
            attr.value = None
            if not attr.inherited:
                attr.inherited = True
        else:
            super().__delattr__(name)
        self._updated.append(name)

    def __str__(self):
        return self._user.name

    def asdict(self) -> dict:
        return asdict(self._user)

    def get_bulk_update_dict(self) -> dict:
        """Returns a dictionary for updating all attributes on a user

        List and dict properties cannot be recorded as having been updated and so
        are always updated

        Returns:
            dict: A dictionary of all properties that have been updated on this user, in the format
                expected by the modifyUserPropGroupBulk.
        """
        update_dict = {}
        for key in self._updated:
            value = getattr(self._user, key)
            print(type(value))
            if isinstance(value, _UserPropValue):
                update_dict[key] = value.value
            else:
                update_dict[key] = value
        for list_key in [
            "dmz_ip",
            "dmz_ipv6",
            "client_to_server_subnets",
            "bypass_subnets",
            "cli_script_connect_win_env",
            "cli_script_connect_mac_env",
        ]:
            update_dict[list_key] = getattr(self._user, list_key)
        return update_dict

    def get_create_dict(self) -> dict:
        """Returns a dictionary for creating a user with all attributes set

        Returns:
            dict: A dictionary of all properties on this user, in the format
                expected by the createUserPropUser API.
        """
        create_dict = {}
        for field in fields(self._user):
            key = field.name
            value = getattr(self._user, key)
            if isinstance(value, _UserPropValue):
                create_dict[key] = value.value
            else:
                create_dict[key] = value
        return create_dict

    def refresh_user(self, **kwargs):
        """Refresh the user with new data from the server.

        This will overwrite any unsaved changes on the user.

        Args:
            **kwargs: The new user data, in the same format as the constructor
        """
        self._user = _User(**kwargs)
        self._updated = []


class UserOperations:
    """Represents the operations we can perform on a given user.

    This class shouldn't be instantiated directly, and instead you should
    access it via AccessServerManagementClient.users.

    This class inherits the methods and attributes from ProfileOperations.

    Args:
        _client (client.RestApiClient): The client we use to communicate with the
            server
    """

    def __init__(self, _client):
        if not isinstance(_client, client.RestApiClient):
            raise TypeError(
                f"Expected 'RestApiClient' for arg '_client', got '{type(client)}'"
            )
        self._client = _client

    @utils.debug_log_call()
    def get(self, user: Union[str, User]) -> User:
        """Retrieves a user from the server using the specified client

        Args:
            user (Union[str, User]): The user to fetch

        Raises:
            AccessServerProfileNotFoundError: Profile does not exist
            AccessServerError: Server returned a different user than requested, something is
                wrong with the server response

        Returns:
            User: Object representing the fetched user
        """
        username = str(user)
        res = self._client.post("/users/list", json={
            "page_size": 1,
            "offset": 0,
            "users": [username],
        })

        if len(res["profiles"]) == 0:
            raise exceptions.AccessServerProfileNotFoundError(
                f'User "{username}" not found on the server'
            )

        if res["profiles"][0]["name"] != username:
            raise exceptions.AccessServerError(
                "Server returned a different user than requested, something is wrong with the "
                "server response"
            )

        return User(**res["profiles"][0])

    @utils.debug_log_call(redact=[2, "password"])
    def create(
        self,
        username: str,
        password: str = None,
        **kwargs,
    ) -> User:
        """Creates a user with the given parameters

        This function will check if the given user exists, and if not will
        create it via a call to /users/create. Then, for every additional
        parameter set, we will update via /userprop/set, deleting the
        user if any errors occur in the process.

        Args:
            username (str): Username of the user to create
            password (str, optional): Password to set for user. If None, no
                password will be set. Must adhere to complexity requirements.
                Defaults to None.
            **kwargs: See the list of supported properties in types._User

        Raises:
            AccessServerProfileExistsError: username provided already exists as
                either a user or a group
            AccessServerConfigError: LocalAuth is not enabled on the server
            ApiClientPasswordComplexityError: Password is not complex enough

        Returns:
            User: A profile representing the user just created
        """
        # Try to create the user and delete profile if any step fails
        logger.info(f'Creating user "{username}"')
        self._client.request_text("POST", "/users/create", json={"name": username})
        try:
            self.update(username, **kwargs)
            if password is not None:
                logger.debug(f'Setting password on profile "{username}"')
                self.change_password(username, password)
        except pyovpn_as.api.exceptions.ApiClientBaseException as api_err:
            logger.error(
                f'Could not create user "{username}", '
                "aborting and deleting user..."
            )
            self.delete(username)
            raise exceptions.AccessServerProfileCreateError(
                "Encountered an issue when setting properties on new user"
            ) from api_err
        else:
            logger.debug(f"Fetching created profile for return...")
            return self.get(username)

    @utils.debug_log_call(redact=[2, "new_password"])
    def change_password(self, user: Union[str, User], new_password: str) -> None:
        """Change the password for a given user

        Args:
            user (Union[str, User]): The user whose password we want to
                change
            new_password (str): The new password to set for the user
        """
        username = str(user)

        # Validate user exists and has local auth enabled
        self.get(username)
        local_auth_status= self._client.get("/server/status")["auth_module_status"]["local"]
        if local_auth_status != "enabled":
            raise exceptions.AccessServerConfigError(
                "Changing a user's password requires local auth to be enabled on the server"
            )

        # Set the password
        self._client.post("/auth/password/change", json={
            "username": username,
            "new_password": new_password,
        })

    @utils.debug_log_call()
    def update(self, user: Union[str, User], **kwargs) -> User:
        """Bulk update user properties

        Args:
            user (Union[str, User]): The user to update
            **kwargs: The properties to update

        Returns:
            User: The updated user
        """
        username = str(user)
        user = self.get(username)  # Validate user exists and is a user

        if len(kwargs) == 0:
            logger.debug("No properties to update, returning user as is")
            return user
        self._client.post("/userprop/set", json={
            "name": username,
            **kwargs
        })
        return self.get(username)

    @utils.debug_log_call()
    def create_connection_profile(self, user: Union[str, User], profile_type: str) -> str:
        """Creates a new connection profile for a given user

        Note that you cannot retrieve the .ovpn configuration after it has been created

        Args:
            user (Union[str, User]): User to generate the connection profile for
            profile_type (str): Type of connection profile to create, one of "autologin", "userlogin",
                "generic", or "epki-generic". See the Access Server API documentation for more
                details on these profile types.

        Returns:
            str: The .ovpn configuration for the new connection profile
        """
        username = str(user)

        self.get(username)
        return self._client.request_text("POST", "/profiles/create", json={
            "user": username,
            "type": profile_type,
            "comment": "Created by pyovpn-as",
        })

    @utils.debug_log_call()
    def delete(self, user: Union[str, User]) -> None:
        """Deletes a user from the server

        Args:
            user (Union[str, User]): User to delete

        Raises:
            AccessServerProfileNotFoundError: User we are trying to delete does
                not exist
            AccessServerProfileDeleteError: Could not delete the profile for
                an unknown reason
        """
        username = str(user)
        # Check user exists and is a user
        self.get(username)

        # Delete the user and revoke certs
        self._client.post("/profiles/delete-user", json={"users": [username]})
        self._client.post("/users/delete", json={"users": [username]})

    @utils.debug_log_call()
    def ban(self, user: Union[str, User]) -> None:
        """Ban a user from connecting to the VPN

        Args:
            user (Union[str, User]): The user to ban from the VPN

        Raises:
            AccessServerProfileNotFoundError: User does not exist on the server.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user
        """
        username = str(user)
        self.get(username)
        self.update(username, deny=True)

    @utils.debug_log_call()
    def list(self) -> list:
        """Lists all users present on the server

        Returns:
            list[User]: A list of all user profiles on the target server
        """
        data = self._client.post("/users/list", json={})
        return [User(**d) for d in data["profiles"]]


'''
    @utils.debug_log_call()
    def kick_user(
        self, user: Union[str, User], reason: str = "", force: bool = False
    ) -> int:
        """Kick all sessions for a given user and return the number of
        connections that were kicked

        Args:
            user (Union[str, User]): The user who we want to kick
            reason (str): The reason to log on the server and to the user for
                kicking said user
            force (bool): Ban a user immediately after disconnecting them, to
                prevent clients from attempting to reconnect

        Raises:
            AccessServerProfileNotFoundError: User does not exist on the server.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user

        Returns:
            int: The number of connections that were killed
        """
        self.get_user(user)
        username = str(user)
        num_disconnected = self._sacli.DisconnectUser(
            username, reason=reason, client_reason=reason
        )
        if force:
            self.ban_user(username)
        return num_disconnected

    @utils.debug_log_call()
    def add_user_to_group(
        self,
        user: Union[str, User],
        group: Union[str, GroupProfile],
        force_overwrite: bool = False,
    ) -> None:
        """Add a given user to the given group by setting the conn_group
        property on the user

        Args:
            user (Union[str, User]): User to add to the group
            group (Union[str, GroupProfile]): Group to add the user to
            force_overwrite (bool): Add a user to the new group even if they
                are already a part of another group

        Raises:
            AccessServerProfileNotFoundError: If either the group or user does
                not exist
            AccessServerProfileExistsError: If either the group or user names
                are not names of what they are meant to represent, ie user is
                actually a group and vice versa
            AccessServerPropOverwriteError: User is already part of a group,
                and the force_overwrite option is not True
        """
        username = str(user)
        group_name = str(group)

        user_profile = self.get_user(username)
        group_operations = GroupOperations(self._sacli)
        group_operations.get_group(group_name)
        if user_profile.has_group and not force_overwrite:
            raise exceptions.AccessServerPropOverwriteError(
                f"User '{username}' is already part of the group "
                f"'{user_profile.conn_group}'. Remove the user from this "
                "group or call this method with force_overwrite=True"
            )
        elif user_profile.has_group:  # and force_overwrite
            logger.warning(
                f"User '{username}' has conn_group='{user_profile.conn_group}',"
                " overwriting with new group..."
            )

        self._sacli.UserPropPut(
            username, "conn_group", group_name, user_profile.is_hidden
        )

    @utils.debug_log_call()
    def remove_user_from_group(self, user: Union[str, User]) -> None:
        """Remove the given user from the group they are a part of

        Args:
            user (Union[str, User]): The user from which to remove from
                their group

        Raises:
            AccessServerProfileNotFoundError: User does not exist on the server.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user
        """
        username = str(user)
        user_profile = self.get_user(username)
        if not user_profile.has_group:
            logger.debug(f"User not a part of a group, nothing has changed")
        self._sacli.UserPropDel(username, "conn_group")

    @utils.debug_log_call()
    def set_user_local_password(
        self,
        user: Union[str, User],
        new_pass: str,
        cur_pass: str = None,
        ignore_checks: bool = False,
    ) -> None:
        """Set the password for a user if using local auth

        Args:
            user (Union[str, User]): The user whose password is to be changed
            new_pass (String): New password
            cur_pass (String, default=None) Current password
            ignore_checks (bool, default=True) Ignore checks

        Raises:
            AccessServerProfileNotFoundError: User does not have a user/pass
                login connection profile configured or user does not exist.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user
        """
        username = str(user)

        # Validate user exists
        self.get_user(username)

        # Set the password
        self._sacli.SetLocalPassword(username, new_pass, cur_pass, ignore_checks)
'''
