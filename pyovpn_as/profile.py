"""Contains the class which represents a profile on the server. This class is
rarely used directly and is rather subclassed into the User and Group classes.
"""
from . import exceptions

class Profile:
    """Represents a profile on the OpenVPN Access Server and provides a logical
    layer to extract meaning from the properties set on the profiles.

    The profile doesn't have to exist on the server for this class to be instantiated, and can be passed as an argument to functions manipulating users, groups, and profiles.

    Args:
        **attrs (dict[str, Any]): The dictionary containing the attributes for a
            profile. This can be fetched from the server with RemoteSacli
            UserPropGet
    """
    def __init__(self, **attrs):
        for key in attrs:
            if not isinstance(key, str):
                raise TypeError(
                    'Attributes for a profile must have keys that are all '
                    'strings'
                )
        self._attrs = attrs
    
    @property
    def is_banned(self) -> bool:
        """bool: Whether or not the profile is banned.
        
        Derived from the ``prop_deny`` property.

        Default behaviour is False
        """
        prop = self._attrs.get('prop_deny', '')
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
        prop = self._attrs.get('prop_superuser', '')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_superuser must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'
    
    @property
    def is_group(self) -> bool:
        """bool: Whether or not the profile represents a group. True when the 
        ``type`` property is equal to 'group'
        """
        return self._attrs.get('type') == 'group'

    @property
    def can_change_password(self) -> bool:
        """bool: Whether or not users derived from this profile can change
        their password via the web interface.
        
        Derived from the ``prop_pwd_change`` property.

        Default behaviour is False
        """
        prop = self._attrs.get('prop_pwd_change', '')
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
        prop = self._attrs.get('prop_autologin', '')
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
        prop = self._attrs.get('prop_pwd_strength', 'true')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_pwd_strength must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'

    @property
    def will_autogenerate_client(self) -> bool:
        """bool: Whether or not the server will autogenerate a connection profile for users derived from this profile. If set to true and the given user tries to access their client, the server will generate one if it doesn't exist.
        
        Derived from the ``prop_autogenerate`` property.
        
        Default behaviour is True.
        """
        prop = self._attrs.get('prop_autogenerate', 'true')
        if not isinstance(prop, str):
            raise exceptions.AccessServerProfileIntegrityError(
                f'Type of prop_autogenerate must be str, not a {type(prop)}'
            )
        return prop.lower() == 'true'
