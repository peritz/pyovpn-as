"""Contains the classes which represents profiles on the server.

Some notes on profiles:

* If you want to make a group, you can't just pass ``type='group'``, you also have to declare ``group_declare='true'``
* You can't change the type manually, the properties that are set determine what type the record is
* Passing noui as True to UserPropPut does not change anything if
    * ``type`` is ``user_compile`` (due to prop_superuser being set)
    * ``group_declare`` is True
"""

import logging
from typing import Any, Union
from dataclasses import dataclass, field, fields

import pyovpn_as.api.exceptions

from . import exceptions

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class _DMZIP:
    """DMZ IP and port that will be forwarded to the client

    Attributes:
        ip (str): The external IP address of the Access Server
        protocol (str): The protocol, one of 'tcp', 'udp', or 'icmp'
        start_port (int): The starting port for the dmz. If not specified all ports will be
            forwarded.
        end_port (int): The ending port for the dmz. If not specified and start_port is specified,
            only the start_port will be forwarded.
    """

    ip: str
    protocol: str
    start_port: int = None
    end_port: int = None


@dataclass(kw_only=True)
class _IPSubnet:
    """Represents an IP subnet

    Attributes:
        ipv6 (bool): Whether or not this is an IPv6 subnet. If false, this is an IPv4 subnet
        netip (string): IP address value
        prefix_length (int): Prefix length of the subnet
    """

    ipv6: bool
    netip: str
    prefix_length: int


@dataclass(kw_only=True)
class _UserPropValue:
    """Represents a value for a UserProp property for both user and group

    Attributes:
        value (Union[str, bool]): The value of the property. This can be a string or a
            boolean.
        inherited (bool): Whether or not the property is inherited from a group or default
            profile.
        inherited_source_type (str): The type of profile the property is inherited from.
            This can be one of 'group', 'default', 'implicit_default', or 'configuration'.
        inherited_source_name (str): The name of the profile the property is inherited from.
    """

    value: Union[str, bool] = None
    inherited: bool = False
    inherited_source_type: str = None
    inherited_source_name: str = None


@dataclass(kw_only=True)
class _UserProp:
    """Represents a UserProp record common to both user and group

    Attributes:
        name (str): The name of the User or Group
        deny (_UserPropValue): If true cannot connect or login
        deny_web (_UserPropValue): If true cannot log in to web interface, but can still connect
        compile (_UserPropValue): If true, the type is 'user_compile' instead of 'user_connect'
            and user record is also queried on nftables/iptables compile and not only on connect
        admin (_UserPropValue): If true, the user is a superuser and has access to all groups and properties
        autologin (_UserPropValue): If true, users can download autologin profiles themselves
        auth_method (_UserPropValue): The auth method that will be used for the user. Maps to user_auth_type
            and default configuration, etc.
        cc_commands (_UserPropValue): Custom OpenVPN directives that will be imported for the user
            on the server side
        totp (_UserPropValue): Specifies whether TOTP based MFA is required
        password_strength (_UserPropValue): Password strength check is enforced when changing the
            password for local auth
        allow_password_change (_UserPropValue): Whether or not users can change their own password
            via the web interface. Admins can always change user passwords including their own
        reroute_gw (_UserPropValue): One of 'disable' and 'dns_only', or 'global'. Disables
            redirection of the default route and/or DNS on the client. This does not block it on
            the backend. If blocking on the backend is required, access lists should be added in
            addition. Defaults to 'global' if not set.
        allow_generate_profiles (_UserPropValue): Allow users themselves to generate connection
            profiles.
        bypass_subnets (list[_IPSubnet]): Subnets or hosts that are installed as bypass routes
            on the client, i.e. that will bypass the VPN and use the normal non-VPN connection.
    """

    name: str
    deny: _UserPropValue = field(default_factory=_UserPropValue)
    deny_web: _UserPropValue = field(default_factory=_UserPropValue)
    compile: _UserPropValue = field(default_factory=_UserPropValue)
    admin: _UserPropValue = field(default_factory=_UserPropValue)
    autologin: _UserPropValue = field(default_factory=_UserPropValue)
    auth_method: _UserPropValue = field(default_factory=_UserPropValue)
    cc_commands: _UserPropValue = field(default_factory=_UserPropValue)
    totp: _UserPropValue = field(default_factory=_UserPropValue)
    password_strength: _UserPropValue = field(default_factory=_UserPropValue)
    allow_password_change: _UserPropValue = field(default_factory=_UserPropValue)
    reroute_gw: _UserPropValue = field(default_factory=_UserPropValue)
    allow_generate_profiles: _UserPropValue = field(default_factory=_UserPropValue)
    bypass_subnets: list[_IPSubnet] = field(default_factory=list)


@dataclass(kw_only=True)
class _UserPropScripts:
    """Represents the scripts that can be set on a user or group profile

    Attributes:
        cli_script_connect_win_user_connect (_UserPropValue): Windows user connection script
        cli_script_connect_win_user_disconnect (_UserPropValue): Windows user disconnection script
        cli_script_connect_win_admin_connect (_UserPropValue): Windows admin connection script
        cli_script_connect_win_admin_disconnect (_UserPropValue): Windows admin disconnection script
        cli_script_connect_mac_user_connect (_UserPropValue): Mac user connection script
        cli_script_connect_mac_user_disconnect (_UserPropValue): Mac user disconnection script
        cli_script_connect_mac_admin_connect (_UserPropValue): Mac admin connection script
        cli_script_connect_mac_admin_disconnect (_UserPropValue): Mac admin disconnection script
        cli_script_connect_win_env (dict): A dictionary mapping environment variable names to
            values for Windows connection scripts
        cli_script_connect_mac_env (dict): A dictionary mapping environment variable names to
            values for Mac connection scripts
    """

    cli_script_connect_win_user_connect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_win_user_disconnect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_win_admin_connect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_win_admin_disconnect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_mac_user_connect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_mac_user_disconnect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_mac_admin_connect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_mac_admin_disconnect: _UserPropValue = field(
        default_factory=_UserPropValue
    )
    cli_script_connect_win_env: dict[str, str] = field(default_factory=dict)
    cli_script_connect_mac_env: dict[str, str] = field(default_factory=dict)


@dataclass(kw_only=True)
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

    password_defined: bool = False
    mfa_status: str = "disabled"
    totp_locked: bool = False
    group: str = None
    static_ipv4: str = None
    static_ipv6: str = None
    dmz_ip: list[_DMZIP] = field(default_factory=list)
    dmz_ipv6: list[_DMZIP] = field(default_factory=list)
    compile: bool = False
    totp_secret: str = None
    totp_admin_only: bool = False
    client_to_server_subnets: list[_IPSubnet] = field(default_factory=list)


@dataclass(kw_only=True)
class _User(_UserPropScripts, _UserLevelOnlyProps, _UserProp):
    """Represents the full set of properties that can be set on a user profile"""

    def __post_init__(self):
        # Sets any dict properties intended to be custom dataclasses to those dataclasses
        for field in fields(self):
            if (
                isinstance(getattr(self, field.name), dict)
                and field.type == _UserPropValue
            ):
                setattr(self, field.name, _UserPropValue(**getattr(self, field.name)))
            elif (
                isinstance(getattr(self, field.name), list)
                and field.type == list[_DMZIP]
            ):
                setattr(
                    self,
                    field.name,
                    [
                        (_DMZIP(**item) if isinstance(item, dict) else item)
                        for item in getattr(self, field.name)
                    ],
                )
            elif (
                isinstance(getattr(self, field.name), list)
                and field.type == list[_IPSubnet]
            ):
                setattr(
                    self,
                    field.name,
                    [
                        (_IPSubnet(**item) if isinstance(item, dict) else item)
                        for item in getattr(self, field.name)
                    ],
                )

