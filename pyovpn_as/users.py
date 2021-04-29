"""This module provides the UserOperations class which allows us to define 
high-level functionality for managing users on the sacli server
"""
import hashlib
import logging
from typing import Any, Union

import pyovpn_as.api.exceptions
from pyovpn_as.api import cli

from . import exceptions, utils
from .profile import GroupProfile, UserProfile, ProfileOperations

logger = logging.getLogger(__name__)

class UserOperations(ProfileOperations):
    """Represents the operations we can perform on a given user.

    This class shouldn't be instantiated directly, and instead you should
    access it via AccessServerManagementClient.users.

    This class inherits the methods and attributes from ProfileOperations.

    Args:
        sacli (cli.RemoteSacli): The client we use to communicate with the
            server
    """
    @staticmethod
    def _resolve_username(user: Union[str, UserProfile]) -> str:
        """Takes a string or UserProfile argument and serialize to a username

        Args:
            user (Union[str, UserProfile]): User to get username for

        Returns:
            str: user.username if isinstance(user), user otherwise
        """
        if isinstance(user, UserProfile):
            return user.username
        else:
            return user


    @utils.debug_log_call()
    def get_user(
        self, user: Union[str, UserProfile]
    ) -> UserProfile:
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
        username = self._resolve_username(user)

        profile = self._get_profile(username)
        
        if profile.type == 'group':
            raise exceptions.AccessServerProfileExistsError(
                f'"{username}" is the name of a group, not a user'
            )
        else:
            return UserProfile(username, profile)


    @utils.debug_log_call(redact=[2, 'password'])
    def create_user(
        self,
        user: Union[str, UserProfile],
        password: str=None,
        group: Union[str, GroupProfile]=None,
        generate_client: bool=True,
        **kwargs
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
        if not self._sacli.LocalAuthEnabled():
            raise exceptions.AccessServerConfigError(
                'Creating a user with local password requires local auth to be '
                'enabled on the server'
            )

        username = self._resolve_username(user)
        
        # If there is a group specified, check that it exists
        if isinstance(group, GroupProfile):
            group_name = group.group_name
        else:
            group_name = group

        if group_name is not None:
            if not isinstance(group_name, str):
                raise TypeError(
                    f"Expected str for arg 'group', got {type(group_name)}"
                )
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
            properties['conn_group'] = group_name
        property_list = [
            (p, kwargs.get(p)) for p in (
            'prop_superuser',
            'prop_autologin',
            'prop_deny',
            'prop_pwd_change',
            'prop_pwd_strength',
            'prop_autogenerate'
        )]
        for p_name, p_val in property_list:
            if p_val is None:
                continue
            elif not isinstance(p_val, bool):
                raise TypeError(
                    f"Expected bool for arg '{p_name}', got {type(p_val)}"
                )
            elif p_val:
                properties[p_name] = 'true'
            else:
                properties[p_name] = 'false'
        
        # Try to create the user and delete profile if any step fails
        logger.info(f'Creating user "{username}"')
        if isinstance(user, UserProfile):
            new_prof = self._create_profile(username, user, **properties)
        else:
            new_prof = self._create_profile(username, **properties)
        try:
            if password is not None:
                logger.debug(f'Setting password on profile "{username}"')
                try:
                    # Password complexity checked here
                    self._sacli.SetLocalPassword(
                        username, password, ''
                    )
                except pyovpn_as.api.exceptions.ApiClientParameterError \
                as api_err:
                    logger.warning(
                        'Server does not use SetLocalPassword, setting password'
                        ' manually using SHA256 hash'
                    )
                    # Password complexity checks need to be done manually
                    # Remember we need to keep the profile hidden if it is 
                    # already hidden
                    if self._sacli.is_password_complex(password):
                        sha = hashlib.sha256(password.encode())
                        hide = new_prof.type == UserProfile.USER_CONNECT_HIDDEN
                        self._sacli.UserPropPut(
                            username, 'pvt_password_digest',
                            sha.hexdigest(), hide
                        )
            if generate_client:
                self.create_client_for_user(username)
        except (
            pyovpn_as.api.exceptions.ApiClientBaseException
        ) as api_err:
            logger.error(
                f'Could not create profile "{username}", '
                'aborting and deleting profile...'
            )
            self._sacli.UserPropDelAll(username)
            raise exceptions.AccessServerProfileCreateError(
                'Encountered an issue when setting properties on new user'
            ) from api_err
        else:
            logger.debug(f'Fetching created profile for return...')
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
        username = self._resolve_username(user)

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
                'unknown reason. New client not present on server despite no '
                'returned error'
            )


    @utils.debug_log_call()
    def delete_user(
        self,
        user: Union[str, UserProfile]
    ) -> None:
        """Deletes a user from the server

        Args:
            user (Union[str, UserProfile]): User to delete

        Raises:
            AccessServerProfileNotFoundError: User we are trying to delete does
                not exist
            AccessServerProfileExistsError: username supplied is name of group
                profile
        """
        username = self._resolve_username(user)

        # 1. Check that the user exists
        profile = self.get_user(username)
        
        if profile.is_group:
            raise exceptions.AccessServerProfileExistsError(
                f'Profile "{username}" is a group, not a user'
            )
        
        # 2. Delete the user and revoke certs
        self.revoke_user_certificates(username)
        self._sacli.UserPropDelAll(username)

        # 3. Check that the profile is deleted
        try:
            self._get_profile(username)
        except exceptions.AccessServerProfileNotFoundError:
            return
        else:
            raise exceptions.AccessServerProfileDeleteError(
                f'Could not delete profile "{username}" for an unknown reason'
            )


    @utils.debug_log_call()
    def get_user_login_ovpn_config(
        self,
        user: Union[str, UserProfile]
    ) -> str:
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
        username = self._resolve_username(user)
            
        # Validate user exists before fetching their config
        self.get_user(username)

        # Use Get1 to prevent config being created in case of not existing
        config = self._sacli.Get1(username)
        if config is None:
            raise exceptions.AccessServerProfileNotFoundError(
                f'Connection profile for user "{username}" could not be found '
                'on the server.'
            )
        else:
            return config[1]


    @utils.debug_log_call()
    def revoke_user_certificates(
        self,
        user: Union[str, UserProfile]
    ) -> None:
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
        username = self._resolve_username(user)

        # Validate user exists
        self.get_user(username)

        # Revoke all certs
        self._sacli.RevokeUser(username)
