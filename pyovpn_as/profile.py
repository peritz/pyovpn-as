"""Contains the classes which represents profiles on the server.

Some notes on profiles:

* If you want to make a group, you can't just pass ``type='group'``, you also have to declare ``group_declare='true'``
* You can't change the type manually, the properties that are set determine what type the record is
* Passing noui as True to UserPropPut does not change anything if
    * ``type`` is ``user_compile`` (due to prop_superuser being set)
    * ``group_declare`` is True
"""
import logging
from typing import Any

import pyovpn_as.api.exceptions
from pyovpn_as.api import cli

from . import exceptions

logger = logging.getLogger(__name__)


class Profile:
    """Represents a profile on the OpenVPN Access Server and provides a logical
    layer to extract meaning from the properties set on the profiles.

    The profile doesn't have to exist on the server for this class to be 
    instantiated, and can be passed as an argument to functions manipulating 
    users, groups, and profiles.

    This class exists primarily as a superclass to User and Group

    Args:
        **attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile. This can be fetched from the server with RemoteSacli
            UserPropGet

    Attributes:
        _attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile provided at ``__init__``
        USER_CONNECT (str): value of ``type`` equal to a profile that is
            evaluated only when a user connects
        USER_CONNECT_HIDDEN (str): value of ``type`` when a profile is
            evaluated the same as USER_CONNECT but is hidden from the admin UI
        USER_COMPILE (str): value of ``type`` when a profile is evaluated on
            iptables compile or when a user connects
        USER_DEFAULT (str): value of ``type`` for the ``__DEFAULT__`` record
        GROUP (str): value of ``type`` for group records
        PROFILE_TYPES (tuple[str]): All types that a profile could be
        USER_TYPES (tuple[str]): List of types valid for a new user
    """
    USER_CONNECT = 'user_connect'
    USER_CONNECT_HIDDEN = 'user_connect_hidden'
    USER_COMPILE = 'user_compile'
    USER_DEFAULT = 'user_default'
    GROUP = 'group'

    PROFILE_TYPES = (
        USER_CONNECT, USER_CONNECT_HIDDEN, USER_COMPILE, USER_DEFAULT, GROUP
    )
    
    USER_TYPES = (
        USER_CONNECT, USER_CONNECT_HIDDEN, USER_COMPILE
    )

    def __init__(self, **attrs):
        for key in attrs:
            if not isinstance(key, str):
                raise TypeError(
                    'All property keys must be strings'
                )
            try:
                attrs[key] = str(attrs[key])
            except:
                raise ValueError('All values must be stringable')
        # Set attributes using Python magic to avoid issues in self.__setattr__
        # We set it twice, once so it is recognised in self.__setattr__ and 
        # again to help with linting
        object.__setattr__(self, '_attrs', {})
        self._attrs = attrs

        # Now force a profile type resolve
        object.__setattr__(self, 'type', self.USER_CONNECT)
        self._resolve_type()


    @property
    def is_hidden(self) -> bool:
        """bool: Whether or not a profile is hidden from the admin interface
        
        True when ``type`` is equal to ``user_connect_hidden``
        """
        return self.type == self.USER_CONNECT_HIDDEN
    

    @property
    def is_banned(self) -> bool:
        """bool: Whether or not the profile is banned.
        
        Derived from the ``prop_deny`` property.

        Default behaviour is False
        """
        prop = self.props.get('prop_deny', '')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_deny must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'
    
    
    @property
    def is_admin(self) -> bool:
        """bool: Whether or not the profile is a superuser/admin.
        
        Derived from the ``prop_superuser`` property.

        Default behaviour is False
        """
        prop = self.props.get('prop_superuser', '')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_superuser must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'
    

    @property
    def is_group(self) -> bool:
        """bool: Whether or not the profile represents a group. True when the 
        ``group_declare`` property is equal to true
        """
        prop = self.props.get('group_declare', '')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of group_declare must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'


    @property
    def can_change_password(self) -> bool:
        """bool: Whether or not users derived from this profile can change
        their password via the web interface.
        
        Derived from the ``prop_pwd_change`` property.

        Default behaviour is False
        """
        prop = self.props.get('prop_pwd_change', '')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_pwd_change must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'


    @property
    def can_autologin(self) -> bool:
        """bool: Whether or not users derived from this profile can download a 
        connection profile which allows them to connect without a password.
        
        Derived from the ``prop_autologin`` property.

        Default behaviour is False
        """
        prop = self.props.get('prop_autologin', '')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_autologin must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'


    @property
    def will_check_password_strength(self) -> bool:
        """bool: Whether the server should check the password strength when a 
        user derived from this profile tries to change it.
        
        Derived from the ``prop_pwd_strength`` property.

        Default behaviour is True
        """
        prop = self.props.get('prop_pwd_strength', 'true')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_pwd_strength must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'


    @property
    def will_autogenerate_client(self) -> bool:
        """bool: Whether or not the server will autogenerate a connection 
        profile for users derived from this profile. If set to true and the 
        given user tries to access their client, the server will generate one 
        if it doesn't exist.
        
        Derived from the ``prop_autogenerate`` property.
        
        Default behaviour is True.
        """
        prop = self.props.get('prop_autogenerate', 'true')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_autogenerate must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'

    
    @property
    def props(self) -> dict:
        """dict[str, Any]: The properties set on the profile

        When this is requested, we immediately resolve the type in the case 
        that anything has changed
        """
        self._resolve_type()
        return self._attrs


    def get_prop(self, key: str) -> Any:
        """Get a property from the profile

        Args:
            key (str): The property key to get

        Returns:
            Any: The value at that key

        Raises:
            KeyError: No property defined for that key
        """
        value = self.props.get(
            key, KeyError(
                f"No value for key '{key}' defined."
            )
        )
        if isinstance(value, KeyError):
            raise value
        return value


    def __getattr__(self, attribute: str) -> Any:
        """If we can't get the attribute from regular means, this function is 
        called as a fallback

        In this case we try to fetch the attribute as though it were a property 
        of the profile we were searching for.

        Args:
            attribute (str): The attribute we are searching for

        Returns:
            Any: The value of the attribute from the properties of the profile

        Raises:
            AttributeError: When the property doesn't exist
        """
        value = self.props.get(
            attribute,
            AttributeError(
                f"'{self.__class__.__name__}' object has no attribute "
                f"'{attribute}'"
            )
        )
        if isinstance(value, AttributeError):
            raise value
        return value


    def __setattr__(self, key, value):
        """Sets a property on the profile unless it exists as an attribute on 
        the object. We also evaluate the type of profile we are dealing with

        Args:
            key (str): The property to set
            value (Any): The value of the property
        """
        try:
            self.__getattribute__(key)
        except AttributeError:
            self._attrs[key] = str(value)
            self._resolve_type()
        else:
            object.__setattr__(self, key, value)


    def _resolve_type(self):
        """Resolves the type of profile this is

        Type resolving is based on the following rules:

        * If ``group_declare`` is true, ``type = group``
        * If ``prop_superuser`` is true, ``type = user_compile``
        * If ``inherit``, ``conn_ip``, ``c2s_route``, ``access_from/access_to``, ``dmz_ip``, 
        or ``bypass_route`` are specified, ``type = user_compile``
        * If ``type = user_connect_hidden`` we leave it as is
        * If ``type = user_default`` we leave it as is, but dealing with the 
        default group may cause issues
        * Otherwise type is ``user_connect``
        """
        prof_type = self._attrs.get('type')
        prop_superuser = self._attrs.get('prop_superuser')
        group_declare = self._attrs.get('group_declare')

        if isinstance(group_declare, str) \
            and group_declare.lower() == 'true':
            self._attrs['type'] = self.GROUP
        elif (
            isinstance(prop_superuser, str)
            and prop_superuser.lower() == 'true'
        ) or 'conn_ip' in self._attrs or 'inherit' in self._attrs:
            self._attrs['type'] = self.USER_COMPILE
        else:
            for key in self._attrs:
                if key.startswith((
                    'c2s_route', 'access_from', 'access_to',
                    'dmz_ip', 'bypass_route'
                )):
                    self._attrs['type'] = self.USER_COMPILE
                    break
            if isinstance(prof_type, str) \
                and prof_type.lower() == self.USER_CONNECT_HIDDEN:
                self._attrs['type'] = self.USER_CONNECT_HIDDEN
            if isinstance(prof_type, str) \
                and prof_type.lower() == self.USER_DEFAULT:
                self._attrs['type'] = self.USER_DEFAULT
            else:
                self._attrs['type'] = self.USER_CONNECT   
        self.type = self._attrs['type']     


class UserProfile(Profile):
    """Represents a user's profile on the server.

    This class encapsulates a user's profile on the server (whether or not it 
    exists or not) and provides a logical layer through which we can make sense 
    of a user's properties. This way, we are able to determine if a user is a 
    superuser by checking both their properties and the properties of the group 
    that they are a part of.

    Args:
        username (str): The name of the user whose profile we are representing
        profile (Profile, optional): The profile to derive our attributes from.
            Defaults to None.
        **attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile. This can be fetched from the server with RemoteSacli
            UserPropGet. Any properties defined here will take precedence over 
            those defined in the profile argument
    
    Raises:
        AccessServerProfileIntegrityError: Properties passed do not match a
            UserProfile

    Attributes:
        username (str): The name of the user whose profile we are representing
        _attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile provided at ``__init__``
    """
    def __init__(self, username: str, profile: Profile=None, **attrs):
        if profile is not None and not isinstance(profile, Profile):
            raise TypeError(
                f"Expected 'Profile' for arg 'profile', got {type(profile)}"
            )
        elif profile is not None:
            props = profile._attrs
        else:
            props = {}

        for key, value in attrs.items():
            props[key] = value

        super().__init__(**props)
        if self.type not in self.USER_TYPES:
            raise exceptions.AccessServerProfileIntegrityError(
                f"Properties given do not describe a UserProfile"
            )
        # __setattr__ issues, see Profile class
        object.__setattr__(self, 'username', username)
        self.username = username


    @property
    def has_group(self):
        """bool: Whether or not ``conn_group`` is set"""
        return self.props.get('conn_group') is not None


    def __str__(self):
        """Username of the profile"""
        return self.username

    
    def __setattr__(self, key: str, value: Any):
        """Prevent setting an attribute that would cause the profile to become 
        a group profile

        Args:
            key (str): Name of the attribute to set
            value (Any): Value to set the attribute to

        Raises:
            AccessServerProfileIntegrityError: Tried to set a property that
                would cause the profile to become a group
        """
        if (
            key == 'group_declare'
            and str(value).lower() == 'true'
        ):
            raise exceptions.AccessServerProfileIntegrityError(
                'Attempt made to set group_declare to a true value on a '
                'UserProfile. This is an illegal operation.'
            )
        super().__setattr__(key, value)



class GroupProfile(Profile):
    """Represents a group profile on the server

    This class encapsulates a group and its properties on the server (whether 
    it exists or not) and provides a logical layer through which we can make 
    sense of its properties. We also provide some assurance that the integrity 
    of the group's userprop profile is maintained.

    Args:
        group_name (str): The name of the group whose profile we are
            representing
        profile (Profile, optional): The profile to derive our attributes from.
            Defaults to None.
        **attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile. This can be fetched from the server with RemoteSacli
            UserPropGet. Any properties defined here will take precedence over 
            those defined in the profile argument

    Attributes:
        group_name (str): The name of the group whose profile we are
            representing
        _attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile provided at ``__init__``
    """
    def __init__(self, group_name: str, profile: Profile, **attrs):
        if profile is not None and not isinstance(profile, Profile):
            raise TypeError(
                f"Expected 'Profile' for arg 'profile', got {type(profile)}"
            )
        elif profile is not None:
            props = profile._attrs
        else:
            props = {}

        for key, value in attrs.items():
            props[key] = value

        super().__init__(**props)
        if not self.is_group:
            raise exceptions.AccessServerProfileIntegrityError(
                'Properties given do not describe a GroupProfile'
            )
        # __setattr__ issues, see Profile class
        object.__setattr__(self, 'group_name', group_name)
        self.group_name = group_name


    def __str__(self):
        """Returns the group name of the profile"""
        return self.group_name

    
    def __setattr__(self, key: str, value: Any):
        """Prevent setting an attribute that would cause the profile to become 
        a user profile

        Args:
            key (str): Name of the attribute to set
            value (Any): Value to set the attribute to

        Raises:
            AccessServerProfileIntegrityError: Tried to set a property that
                would cause the profile to become a user
        """
        if (
            key == 'group_declare'
            and str(value).lower() != 'true'
        ):
            raise exceptions.AccessServerProfileIntegrityError(
                'Attempt made to set group_declare to a false value on a '
                'GroupProfile. This is an illegal operation.'
            )
        super().__setattr__(key, value)



class ProfileOperations:
    """A class representing the operations that can take place against a 
    userprop profile.

    This class should not be instantiated directly, and is generally only used 
    to subclass for GroupOperations and UserOperations. This is the reason for 
    making all methods protected.

    Args:
        sacli (cli.RemoteSacli): The client we use to communicate with the
            server
    
    Attributes:
        _sacli (cli.RemoteSacli): The client we use to communicate with the 
            server
    """
    def __init__(self, sacli: cli.RemoteSacli):
        if not isinstance(sacli, cli.RemoteSacli):
            raise TypeError(
                f"Expected 'RemoteSacli' for arg 'sacli', got '{type(sacli)}'"
            )
        self._sacli = sacli


    def _get_profile(self, profile_name: str) -> Profile:
        """Get the userprop profile given by the profile name

        Args:
            profile_name (str): The profile to get from the server

        Raises:
            AccessServerProfileNotFoundError: Profile does not exist

        Returns:
            Profile: Profile representing the userprop profile
        """
        profile_dict = self._sacli.UserPropGet(pfilt=[profile_name,])
        profile = profile_dict.get(profile_name)
        if profile is None:
            raise exceptions.AccessServerProfileNotFoundError(
                f'Could not find profile for "{profile_name}"'
            )
        return Profile(**profile)


    def _create_profile(
        self,
        profile_name: str,
        profile: Profile=None,
        **properties
    ) -> Profile:
        """Create a userprop profile on the server using the profile provided

        Args:
            profile_name (str): Name of the record to insert
            profile (Profile, optional): The profile to create. Default is None
            **properties: Any additional properties to set on the target. These 
                will take precedence over any properties defined in the profile

        Returns:
            Profile: The profile that was created

        Raises:
            AccessServerProfileExistsError: profile provided already exists as
                either a user or a group
        """
        if profile is not None and not isinstance(profile, Profile):
            raise TypeError(
                f"Expected 'Profile' for arg 'profile', got '{type(profile)}'"
            )
        # Check for existence of profile
        try:
            self._get_profile(profile_name)
        except exceptions.AccessServerProfileNotFoundError:
            pass
        else:
            raise exceptions.AccessServerProfileExistsError(
                f'Profile for "{profile_name}" already exists on the server'
            )

        # Resolve the properties we need to add to the profile
        if profile is None:
            new_props = properties
        else:
            new_props = {}
            keys = set(list(properties.keys()) + list(profile.props.keys()))
            for k in keys:
                if k in properties:
                    new_props[k] = properties[k]
                else:
                    new_props[k] = profile.props[k]

        # Create new profile object (checks integrity of attributes)
        new_profile = Profile(**new_props)
        
        try:
            # Set properties required on the new profile
            # Profile will always contain at least the type of user
            for key, value in new_profile.props.items():
                logger.debug(
                    f'Setting property "{key}" on profile "{profile_name}"'
                )
                self._sacli.UserPropPut(
                    profile_name, key, value, new_profile.is_hidden
                )

        except (
            pyovpn_as.api.exceptions.ApiClientBaseException,
            exceptions.AccessServerClientExistsError
        ) as api_err:
            logger.error(
                f'Could not create profile "{profile_name}", '
                'aborting and deleting profile...'
            )
            self._sacli.UserPropDelAll(profile_name)
            raise exceptions.AccessServerProfileCreateError(
                'Encountered an issue when setting properties on new profile'
            ) from api_err
        else:
            logger.debug(f'Fetching created profile for return...')
            return self._get_profile(profile_name)

    
    def _delete_profile(self, profile_name: str) -> None:
        """Delete a given profile from the server

        Args:
            profile_name (str): Profile to delete

        Raises:
            AccessServerProfileNotFoundError: Profile does not exist
            AccessServerProfileDeleteError: Could not delete the profile for
                an unknown reason
        """
        self._sacli.UserPropDelAll(profile_name)

        # Check that the profile is deleted
        try:
            self._get_profile(profile_name)
        except exceptions.AccessServerProfileNotFoundError:
            return
        else:
            raise exceptions.AccessServerProfileDeleteError(
                f'Could not delete profile "{profile_name}" for an unknown '
                'reason'
            )


    def _ban_profile(self, profile_name: str) -> None:
        """Ban users derived from this profile from connecting to the VPN

        Args:
            profile_name (str): Profile to ban

        Raises:
            AccessServerProfileNotFoundError: Profile does not exist
        """
        profile = self._get_profile(profile_name)
        self._sacli.UserPropPut(
            profile_name, 'prop_deny', 'true', profile.is_hidden
        )
