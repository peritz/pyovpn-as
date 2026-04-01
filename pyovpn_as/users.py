"""This module provides the UserOperations class which allows us to define
high-level functionality for managing users on the sacli server
"""

import hashlib
import logging
from typing import Union
from dataclasses import dataclass

import pyovpn_as.api.exceptions

from . import exceptions, utils
from .profile import _IPSubnet, _DMZIP, _UserProp, _UserPropScripts

logger = logging.getLogger(__name__)


@dataclass
class _UserLevelOnlyProps:
    """Represents the properties that only apply to user profiles, and not group profiles

    Attributes:
        password_defined (bool): Whether or not a local password is defined for this user
        mfa_status (str): The status of MFA. This is read-only that combines totp and totp_locked
            into a single status. One of 'pending', 'disabled', or 'enrolled'.
        totp_locked (bool): Specifies if the TOTP for the user is locked/enrolled. If true, secret
            is no longer viewable.
        group (str): The group the user is part of
        static_ipv4 (str): The static IP assigned to the user, if any
        static_ipv6 (str): The static IPv6 assigned to the user, if any
        dmz_ip (list[_DMZIP]): The IPv4 addresses and port ranges that are exposed on the client
        dmz_ipv6 (list[_DMZIP]): The IPv6 addresses and port ranges that are exposed on the client
        compile (bool): Whether or not the user is type 'user_compile' or 'user_connect'.
        totp_secret (str): The TOTP secret code, according to RFC 6238. This value might not be
            present for locked users in later versions.
        totp_admin_only (bool): Whether or not only admins can generate and view TOTP secrets.
        client_to_server_subnets (list[_IPSubnet]): Subnets that are behind the client, i.e. the
            client will be a router/gateway for the subnets specified in this array. On the server
            side, this is split into IPv4 and IPv6 subnets, but this API represents that as a
            single list. Use the IPv6 flag of the subnet to determine the address family.
    """

    password_defined: bool
    mfa_status: str
    totp_locked: bool
    group: str
    static_ipv4: str
    static_ipv6: str
    dmz_ip: list[_DMZIP] = field(default_factory=list)
    dmz_ipv6: list[_DMZIP] = field(default_factory=list)
    compile: bool
    totp_secret: str
    totp_admin_only: bool
    client_to_server_subnets: list[_IPSubnet] = field(default_factory=list)


@dataclass
class _User(_UserProp, _UserPropScripts, _UserLevelOnlyProps):
    """Represents the full set of properties that can be set on a user profile"""


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
        """Use None to force the user to inherit the value from their group
        """
        # If attr is a _UserPropValue then we want to override the inherited setting
        attr = getattr(self._user, name)
        if isinstance(attr, _UserPropValue):
            attr.value = value
            if attr.inherited:
                attr.inherited = False
        else:
            super().__setattr__(name, value)
        self._updated = name

    def __delattr__(self, name):
        """Delete an attribute to force the user to inherit the value from their group
        """
        attr = getattr(self._user, name)
        if isinstance(attr, _UserPropValue):
            attr.value = None
            if not attr.inherited:
                attr.inherited = True
        else:
            super().__delattr__(name)
        self._updated = name

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
        for key in self._user.__dataclass_fields__.keys():
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


class UserOperations(ProfileOperations):
    """Represents the operations we can perform on a given user.

    This class shouldn't be instantiated directly, and instead you should
    access it via AccessServerManagementClient.users.

    This class inherits the methods and attributes from ProfileOperations.

    Args:
        sacli (cli.RemoteSacli): The client we use to communicate with the
            server
    """

    @utils.debug_log_call()
    def get_user(self, user: Union[str, UserProfile]) -> UserProfile:
        """Retrieves a user from the server using the specified client

        Args:
            user (Union[str, UserProfile]): The user to fetch

        Raises:
            AccessServerProfileNotFoundError: Profile does not exist
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user

        Returns:
            UserProfile: A dictionary representing the fetched user
        """
        username = str(user)

        profile = self._get_profile(username)

        if profile.type == "group":
            raise exceptions.AccessServerProfileExistsError(
                f'"{username}" is the name of a group, not a user'
            )
        else:
            return UserProfile(username, profile)

    @utils.debug_log_call(redact=[2, "password"])
    def create_user(
        self,
        user: Union[str, UserProfile],
        password: str = None,
        group: Union[str, GroupProfile] = None,
        generate_client: bool = True,
        **kwargs,
    ) -> UserProfile:
        """Creates a user with the given parameters

        This function will check if the given user exists, and if not will
        create it via a call to UserPropPut. Then, for every additional
        parameter set, we will make another call to UserPropPut, deleting the
        user if any errors occur in the process.

        We can pass a UserProfile if we wish, but any arguments we pass after
        that will overwrite any properties set in the UserProfile

        Args:
            user (Union[str, UserProfile]): Username of the user to create,
                or a UserProfile object representing the user to create
            password (str, optional): Password to set for user. If None, no
                password will be set. Must adhere to complexity requirements.
                Defaults to None.
            group (Union[str, GroupProfile], optional): A connection group to
                assign the user to. If set, this user will inherit all options
                that apply to the given group. Will raise an error if group
                does not exist. Defaults to None. Can be a group profile or a
                string
            generate_client (bool, optional): Whether or not to generate a
                certificate and openvpn client configuration file for this user.
                Users cannot connect to the VPN unless this is set to true (or a
                cert is generated later for them). Defaults to True.
            **kwargs:
                prop_superuser (bool, optional): Whether or not to explicitly
                    make this user an administrator. Defaults to None.
                prop_autologin (bool, optional): Whether or not to explicitly
                    allow this user to connect without a username and password.
                    Defaults to None.
                prop_deny (bool, optional): Explicitly deny access to the user.
                    Defaults to None.
                prop_pwd_change (bool, optional): Whether or not to explicitly
                    allow the user to change their password using the WebUI.
                    Defaults to None.
                prop_pwd_strength (bool, optional): Whether or not to
                    explicitly check the complexity of this user's password when
                    they try to change it in the WebUI. Defaults to None.
                prop_autogenerate (bool, optional): Whether or not to prevent
                    the server from automatically regenerating user connection
                    profiles (client records) when they don't exist (e.g.
                    revoked) on the server. Defaults to None

        Raises:
            AccessServerProfileExistsError: username provided already exists as
                either a user or a group
            AccessServerProfileNotFoundError: group given does not exist
            AccessServerConfigError: LocalAuth is not enabled on the server
            ApiClientPasswordComplexityError: Password is not complex enough

        Returns:
            UserProfile: A profile representing the user just created

        TODO Add parameter to hide profile in ui
        TODO explicitly define default behaviour of server in docstring
        TODO Fetch group name from user profile
        TODO tests
        TODO only raise error for local auth if pass not present (in prof too)
        """
        # We're going to be creating a user with a local password
        # Local Auth must therefore be enabled
        if password is not None and not self._sacli.LocalAuthEnabled():
            raise exceptions.AccessServerConfigError(
                "Creating a user with local password requires local auth to be "
                "enabled on the server"
            )

        username = str(user)

        # If there is a group specified, check that it exists
        if isinstance(group, GroupProfile):
            group_name = group.group_name
        else:
            group_name = group

        if group_name is not None:
            if not isinstance(group_name, str):
                raise TypeError(f"Expected str for arg 'group', got {type(group_name)}")
            try:
                group_profile = self._get_profile(group_name)
            except exceptions.AccessServerProfileNotFoundError:
                raise exceptions.AccessServerProfileNotFoundError(
                    f'Group "{group_name}" does not exist'
                )
            if not group_profile.is_group:
                raise exceptions.AccessServerProfileExistsError(
                    f'Profile "{group_name}" is not a group'
                )
            logger.debug(f'Got group "{group_name}"')

        # Collect other parameters
        properties = {}
        if group_name is not None:
            properties["conn_group"] = group_name
        property_list = [
            (p, kwargs.get(p))
            for p in (
                "prop_superuser",
                "prop_autologin",
                "prop_deny",
                "prop_pwd_change",
                "prop_pwd_strength",
                "prop_autogenerate",
            )
        ]
        for p_name, p_val in property_list:
            if p_val is None:
                continue
            elif not isinstance(p_val, bool):
                raise TypeError(f"Expected bool for arg '{p_name}', got {type(p_val)}")
            elif p_val:
                properties[p_name] = "true"
            else:
                properties[p_name] = "false"

        # Try to create the user and delete profile if any step fails
        logger.info(f'Creating user "{username}"')
        if isinstance(user, UserProfile):
            new_profile = self._create_profile(username, user, **properties)
        else:
            new_profile = self._create_profile(username, **properties)
        try:
            if password is not None:
                logger.debug(f'Setting password on profile "{username}"')
                try:
                    # Password complexity checked here
                    self._sacli.SetLocalPassword(username, password, "")
                except pyovpn_as.api.exceptions.ApiClientParameterError as api_err:
                    logger.warning(
                        "Server does not use SetLocalPassword, setting password"
                        " manually using SHA256 hash"
                    )
                    # Password complexity checks need to be done manually
                    # Remember we need to keep the profile hidden if it is
                    # already hidden
                    if self._sacli.is_password_complex(password):
                        sha = hashlib.sha256(password.encode())
                        self._sacli.UserPropPut(
                            username,
                            "pvt_password_digest",
                            sha.hexdigest(),
                            new_profile.is_hidden,
                        )
            if generate_client:
                self.create_client_for_user(username)
        except pyovpn_as.api.exceptions.ApiClientBaseException as api_err:
            logger.error(
                f'Could not create profile "{username}", '
                "aborting and deleting profile..."
            )
            self._sacli.UserPropDelAll(username)
            raise exceptions.AccessServerProfileCreateError(
                "Encountered an issue when setting properties on new user"
            ) from api_err
        else:
            logger.debug(f"Fetching created profile for return...")
            return self.get_user(username)

    @utils.debug_log_call()
    def create_client_for_user(self, user: Union[str, UserProfile]) -> None:
        """Creates a new client record for a given user, or raises an error if
        one exists

        Args:
            user (Union[str, UserProfile]): User to generate the client for

        Raises:
            AccessServerClientExistsError: A client record for the given user
                already exists
        """
        username = str(user)

        # 1. Verify we are creating a client for an existing user
        self.get_user(username)

        # 2. Check if there is already an existing client
        existing_clients = self._sacli.EnumClients()
        if username in existing_clients:
            raise exceptions.AccessServerClientExistsError(
                f'Client record already exists for "{username}"'
            )

        # 3. Create client config and validate it exists
        self._sacli.AutoGenerateOnBehalfOf(username)
        new_existing_clients = self._sacli.EnumClients()
        if username not in new_existing_clients:
            raise exceptions.AccessServerClientCreateError(
                f'Creation of client record for "{username}" failed for an '
                "unknown reason. New client not present on server despite no "
                "returned error"
            )

    @utils.debug_log_call()
    def delete_user(self, user: Union[str, UserProfile]) -> None:
        """Deletes a user from the server

        Args:
            user (Union[str, UserProfile]): User to delete

        Raises:
            AccessServerProfileNotFoundError: User we are trying to delete does
                not exist
            AccessServerProfileExistsError: username supplied is name of group
                profile
            AccessServerProfileDeleteError: Could not delete the profile for
                an unknown reason
        """
        username = str(user)
        # Check user exists and is a user
        self.get_user(username)

        # Delete the user and revoke certs
        self.revoke_user_certificates(username)
        self._delete_profile(username)

    @utils.debug_log_call()
    def get_user_login_ovpn_config(self, user: Union[str, UserProfile]) -> str:
        """Fetches the .ovpn configuration for

        Args:
            user (Union[str, UserProfile]): user to fetch configuration for

        Raises:
            AccessServerProfileNotFoundError: User does not have a user/pass
                login connection profile configured or user does not exist.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user

        Returns:
            str: The unified connection profile for the given user requiring an
                interactive login
        """
        username = str(user)

        # Validate user exists before fetching their config
        self.get_user(username)

        # Use Get1 to prevent config being created in case of not existing
        config = self._sacli.Get1(username)
        if config is None:
            raise exceptions.AccessServerProfileNotFoundError(
                f'Connection profile for user "{username}" could not be found '
                "on the server."
            )
        else:
            return config[1]

    @utils.debug_log_call()
    def revoke_user_certificates(self, user: Union[str, UserProfile]) -> None:
        """Revoke all certificates for the given user

        Args:
            user (Union[str, UserProfile]): User whose certificates we want to
                revoke

        Raises:
            AccessServerProfileNotFoundError: User does not have a user/pass
                login connection profile configured or user does not exist.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user
        """
        username = str(user)

        # Validate user exists
        self.get_user(username)

        # Revoke all certs
        self._sacli.RevokeUser(username)

    @utils.debug_log_call()
    def ban_user(self, user: Union[str, UserProfile]) -> None:
        """Ban a user from connecting to the VPN

        Args:
            user (Union[str, UserProfile]): The user to ban from the VPN

        Raises:
            AccessServerProfileNotFoundError: User does not exist on the server.
            AccessServerProfileExistsError: Username provided is the name of a
                group, not a user
        """
        username = str(user)
        self.get_user(username)
        self._ban_profile(username)

    @utils.debug_log_call()
    def list_users(self) -> list:
        """Lists all users present on the server

        Returns:
            list[UserProfile]: A list of all user profiles on the target server
        """
        profile_dict = self._sacli.UserPropGet(tfilt=list(UserProfile.USER_TYPES))
        return [UserProfile(user, **props) for user, props in profile_dict.items()]

    @utils.debug_log_call()
    def kick_user(
        self, user: Union[str, UserProfile], reason: str = "", force: bool = False
    ) -> int:
        """Kick all sessions for a given user and return the number of
        connections that were kicked

        Args:
            user (Union[str, UserProfile]): The user who we want to kick
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
        user: Union[str, UserProfile],
        group: Union[str, GroupProfile],
        force_overwrite: bool = False,
    ) -> None:
        """Add a given user to the given group by setting the conn_group
        property on the user

        Args:
            user (Union[str, UserProfile]): User to add to the group
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
    def remove_user_from_group(self, user: Union[str, UserProfile]) -> None:
        """Remove the given user from the group they are a part of

        Args:
            user (Union[str, UserProfile]): The user from which to remove from
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
        user: Union[str, UserProfile],
        new_pass: str,
        cur_pass: str = None,
        ignore_checks: bool = False,
    ) -> None:
        """Set the password for a user if using local auth

        Args:
            user (Union[str, UserProfile]): The user whose password is to be changed
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
