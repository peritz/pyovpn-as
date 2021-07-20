"""This module provides functionality similar to that of the sacli tool in
   OpenVPN Access Servers.

Attributes:
    XML_RPC_VAL (TypeVar): The list of types that an XML-RPC parameter is
        allowed to be
"""

import logging
from datetime import datetime
from typing import TypeVar

from pyovpn_as.api.exceptions import (ApiClientParameterError,
                                      ApiClientPasswordComplexityError,
                                      ApiClientPasswordIncorrectError,
                                      ApiClientPasswordResetError)

from .rpc import RpcClient

logger = logging.getLogger(__name__)

XML_RPC_VAL = TypeVar(
    'XML_RPC_VAL',
    str,
    bool,
    int,
    float,
    dict,
    list,
    tuple,
    type(None),
    bytes,
    bytearray,
    datetime
)

class RemoteSacli:
    """A Wrapper around RpcClient that allows us to emulate the functionality of
       the sacli tool provided in OpenVPN Access Server installations.

    This class is essentially a wrapper around the RpcClient which will handle
    multiple XML-RPC calls if needed for a given operation. This class also
    allows us to handle more complex errors returned by the RpcClient.

    Attributes:
        _RpcClient (RpcClient): Client object that we are wrapping

    Args:
        endpoint (str): The XML-RPC endpoint to connect to, usually in the form
            https://<ip-address>/RPC2/
        username (str): Username of an admin user on the server to connect as
        password (str): Password of the above user that we can connect using
        debug (bool, optional): Provide verbose debug output from the RpcClient.
            Defaults to False
        allow_untrusted (bool, optional): Allow endpoint to send SSL cert that
            is unverified or untrusted. This should ideally be turned off in
            production to prevent MITM attacks. Defaults to False.
    
    Raises:
        ValueError: Password contains and illegal character
        ApiClientBaseException: Something went wrong in connecting to the
            AccessServer endpoint
    """
    def __init__(
        self,
        endpoint: str,
        username: str,
        password: str,
        debug=False,
        allow_untrusted=False
    ):
        self._RpcClient = RpcClient(
            endpoint,
            username,
            password, 
            debug=debug,
            allow_untrusted=allow_untrusted
        )

    def __enter__(self):
        return self

    def __exit__(self):
        self.close()
    
    def close(self):
        self._RpcClient.close()


    @staticmethod
    def is_password_complex(new_pass: str) -> bool:
        """Validate that a password is suitably complex for OpenVPN AS

        An OpenVPN Access Server password must be at least 8 characters long and
        contain a digit, an uppercase letter, a lowercase letter and a symbol
        from !@#$%&'()*+,-/[\\]^_`{|}~<>. (full stop included, also note
        absence of colon and double quotation marks).

        Args:
            new_pass (str): Password to check validate

        Raises:
            ApiClientPasswordComplexityError: Password is not complex enough

        Returns:
            bool: True if the password is suitably complex
        """
        complexity_err = ApiClientPasswordComplexityError(
            "New Password must be at least 8 characters. Password must "
            "also contain a digit, an Uppercase letter, and a symbol from "
            "!@#$%&'()*+,-/[\\]^_`{|}~<>."
        )
        # None
        if new_pass is None:
            raise complexity_err
        # Catch someone not passing string
        if not isinstance(new_pass, str):
            raise TypeError(
                'is_password_complex expected new_pass to be str, got '
                f'{type(new_pass)}'
            )
        # Length
        if len(new_pass) < 8:
            raise complexity_err
        # Uppercase lowercase
        if new_pass.upper() == new_pass or new_pass.lower() == new_pass:
            raise complexity_err
        # Digit
        contains_digit = False
        for i in '0123456789':
            if i in new_pass:
                contains_digit = True
                break
        # Symbol
        contains_symbol = False
        for s in "!@#$%&'()*+,-/[\\]^_`{|}~<>.":
            if s in new_pass:
                contains_symbol = True
                break
        if not contains_symbol or not contains_digit:
            raise complexity_err
        
        return True
            

    def UserPropPut(
        self,
        user: str,
        key: str,
        value: XML_RPC_VAL,
        noui: bool=False
    ) -> list:
        """Add a property to a user profile (create user profile if it doesn't
           exist)

        Args:
            user (str): Username of profile to change
            key (str): Property name to put
            value (XML_RPC_VAL): Value of the property
            noui (bool, optional): Hide user profile in the WebUI. Defaults
                to False.

        Returns:
            list[bool, dict]
        """
        self._RpcClient.UserPropPut(user, {key: value}, noui)
        user_profile = self._RpcClient.UserPropProfileMultiGet(pfilt=[user,])
        return self._RpcClient.UserPropReplace(
            user,
            user_profile[user]
        )

    def UserPropGet(
        self,
        pfilt: list=None,
        tfilt: list=None
    ) -> dict:
        """Retrieves a list of profiles from the server, filtering on profile
           name and profile type (e.g. user_connect or user_connect_hidden)

        Args:
            tfilt (list[str], optional): List of profile types to filter by.
                Defaults to None.
            pfilt (list[str], optional): List of profile names to filter by.
                Defaults to None.

        Returns:
            dict[str, dict[str, XML_RPC_VAL]]: Dictionary of profiles retrieved
        """
        return self._RpcClient.UserPropProfileMultiGet(pfilt, tfilt)

    def UserPropDel(
        self,
        user: str,
        key: str
    ) -> list:
        """Delete a property from a profile

        Args:
            user (str): Name of the profile to delete the property from
            key (str): Name of the property to delete

        Returns:
            list[bool, dict]
        """
        self._RpcClient.UserPropDel(user, [key,])
        user_profile = self._RpcClient.UserPropProfileMultiGet(pfilt=[user,])
        return self._RpcClient.UserPropReplace(
            user,
            user_profile[user]
        )

    def UserPropDelAll(self, user:str) -> None:
        """Deletes a profile from the server

        Args:
            user (str): Profile name to delete
        """
        self._RpcClient.UserPropProfileDelete(user)

    def UserPropCount(self, tfilt: list=None) -> int:
        """Count the number of profiles that exist by filtering on profile type

        Args:
            tfilt (list[str], optional): Profile type to filter by. Defaults to
                None.

        Returns:
            int: Number of profiles that match the given filter
        """
        return self._RpcClient.UserPropProfileCount(tfilt)

    def LocalAuthEnabled(self) -> bool:
        """Check if local authentication is enabled on the remote server

        Returns:
            bool: True if Local Authentication is enabled False otherwise
        """
        return self._RpcClient.LocalAuthEnabled()

    def SetLocalPassword(
        self,
        user: str,
        new_pass: str,
        cur_pass: str=None,
        ignore_checks: bool=False
    ) -> dict:
        """Set the password for a user if using local auth

        This function works a little differently to how the CLI function works
        in that unless checks are specifically ignored, we will enforce them.
        
        Further to the above, the API will not allow a password to be set (when
        checks are not ignored) if there is not already a password set for that
        user.
        Therefore, if we get told there is not a password already set, we will
        perform our own password complexity checks, and send the new password,
        whilst ignoring the server checks, allowing us to set a password for a
        first time/newly created user.

        Raises:
            ApiClientParameterError: current password is None and we're not
                ignoring checks, or API has changed
            ApiClientPasswordIncorrectError: Current password supplied is 
                incorrect
            ApiClientPasswordComplexityError: New password is not complex
                enough
            ApiClientPasswordResetError: Something else happened we didn't
                expect

        Args:
            user (str): user to change password for
            new_pass (str): the new password to set
            cur_pass (str, optional): Current password, only needed if
                ignore_checks is False. If user is new you should provide an
                empty password. Defaults to None.
            ignore_checks (bool, optional): Ignore password complexity and
                current password checks. Defaults to False.
        """
        if not ignore_checks and cur_pass is None:
            raise ApiClientParameterError(
                'Must provide current password if not ignoring password checks'
            )
        
        # Check password complexity before sending to server to save pain
        if not ignore_checks:
            self.is_password_complex(new_pass)

        return_val = self._RpcClient.SetLocalPassword(
            user, new_pass, cur_pass, ignore_checks
        )
        # Check if we are trying to set the password for a new user
        if not return_val['status'] \
            and not ignore_checks \
            and return_val['reason'] == \
            'error verifying current password: no current password is defined':
            # Note that we have already checked the complexity of the password
            # if we are not ignoring checks
            return_val = self._RpcClient.SetLocalPassword(
                user, new_pass, None, True
            )
            
        # Was the current password we sent incorrect?
        if not return_val['status'] \
            and not ignore_checks \
            and return_val['reason'] == \
            ('error verifying current password: failed to enter correct current'
            ' password'):
            raise ApiClientPasswordIncorrectError('Failed to enter the '
                f'correct current password for user "{user}"')

        elif not return_val['status']:
            raise ApiClientPasswordResetError(
                'Something unexpected happened while setting password for '
                f'user "{user}": {return_val["reason"]}'
            )
        else:
            return

    def RemoveLocalPassword(self, user: str) -> None:
        """Remove the password from a user when using local auth

        Args:
            user (str): The user for whom to remove the password
        """
        self._RpcClient.RemoveLocalPassword(user)

    def AutoGenerateClient(self) -> None:
        """Generate a client record for the authenticated user if none exists
        """
        self._RpcClient.AutoGenerateClient()

    def AutoGenerateOnBehalfOf(self, user: str) -> None:
        """Generate a client record for a specific user

        The user passed does not have to exist, and essentially amounts to 
        generating a certificate for a common name equal to the username passed

        Args:
            user (str): The user to create the client record for
        """
        self._RpcClient.AutoGenerateOnBehalfOf(user)
    
    def RevokeCert(self, cn: str) -> None:
        """Revoke a client certificate

        Args:
            cn (str): Common name of the certificate to revoke, usually either
                <username> or <username>_AUTOLOGIN
        """
        self._RpcClient.RevokeCert(cn)

    def RevokeUser(self, user: str) -> None:
        """Revoke all certificates belonging to a given user

        Args:
            user (str): The user whose certificates we want to revoke
        """
        return self._RpcClient.RevokeUser(user)

    def GetUserlogin(self, user: str=None) -> str:
        """Get a user-locked connection profile for the given user

        This is equivalent to Get1(user) except that if the configuration does
        not exist on the server it will be created.

        E.g.

            >>> print(client.Get1('doesnotexist'))
            None
            >>> print(client.GetUserlogin('doesnotexist'))
            # Automatically generated OpenVPN client config file
            . . .
            >>> print(client.Get1('doesnotexist'))
            # Automatically generated OpenVPN client config file
            . . .

        Args:
            user (str, optional): User to get connection profile for. Defaults
                to None

        Returns:
            str: the user-locked configuration profile for the given user, or
                the current authenticated user if None
        """
        return self._RpcClient.GetUserlogin(user)

    def Get1(self, cn: str) -> list:
        """Get a unified connection profile for the given common name

        This connection profile can be written to a file for import into most
        OpenVPN clients. It contains all certs and private keys necessary to
        connect to the server.

        Args:
            cn (str): Common name of the certificate to fetch for the profile

        Returns:
            list[str]: The unified connection profile and name of the file for 
                the given common name or None if it doesn't exist
        """
        return self._RpcClient.Get1(cn)

    def EnumClients(self) -> list:
        """Fetch the list of client names in the database where a client is a
           common name that can connect to the VPN

        Returns:
            list[str]: a list of client names
        """
        return self._RpcClient.EnumClients()

    def ConfigQuery(
        self, prof: str=None, plist: list=None
    ) -> dict:
        """Fetch the configuration by filtering on the given search terms

        Args:
            prof (str, optional): Name of the profile to fetch. Defaults to None
            plist (list[str], optional): List of profile filter terms. These
                are profile entries that we want to extract from the results. 
                Essentially, the columns we select. Defaults to None

        Returns:
            dict[str, str]: Configuration found based on search terms, or
                active config if no search terms defined
        """
        return self._RpcClient.ConfigQuery(prof, plist)

    def DisconnectUser(
        self,
        user: str,
        restart: bool=False,
        reason: str=None,
        client_reason: str=None,
        psid: bool=False
    ) -> int:
        """Disconnect a list of users from the VPN

        Args:
            user (str): The list of users to disconnect from the VPN
            restart (bool, optional): Whether or not to restart the client as
                opposed to just halting them. Defaults to False.
            reason (str, optional): The reason logged on the server for the
                disconnection. Defaults to None.
            client_reason (str, optional): The reason sent to the client for
                disconnection. Defaults to None.
            psid (bool, optional): Whether or not to preserve the most recently
                used SessionID. Use this in combination with restart to invite
                the client to reconnect with the same Session ID. Defaults to
                False.

        Returns:
            int: The number of users kicked, though this should just be 1 or 0
        """
        return self._RpcClient.DisconnectUsers(
            [user,], restart, reason, client_reason, psid
        )

    def Version(self) -> str:
        """Get the version of the server we are communicating with

        Returns:
            str: The version of OpenVPN AccessServer the remote server is 
                running
        """
        return self._RpcClient.GetASLongVersion()

    
    def Status(self) -> dict:
        """Get the run status of the server's internal services

        The returned dictionary contains the following keys:

        * errors (dict): A dictionary of any service errors
        * last_restarted (str): The time the server was last restarted
        * service_status (dict[str, Union["on", "off"]]): status of each 
        internal service

        Below are some of the services that may be listed:

        * api: The XML-RPC API
        * auth: Authentication service (depends on backend? TODO clarify)
        * bridge: Network bridge
        * client_query
        * crl: Certificate Revocation List
        * daemon_pre
        * db_push
        * ip6tables_live
        * ip6tables_openvpn
        * iptables_live
        * iptables_openvpn
        * log
        * openvpn_0
        * openvpn_1
        * subscriptiopn
        * user
        * web

        Returns:
            dict[str, Any]
        """
        return self._RpcClient.RunStatus()

    
    def GetVpnStatus(self) -> dict:
        """Returns a detailed breakdown of the status of the VPN and the client 
        connections

        The resulting dictionary contains a key/value pair for each VPN daemon 
        process. The default configuration likely leaves two open, one 
        internally and the other external for users outside the local network 
        to connect to. They will be called ``openvpn_X`` where 0 is the 
        internal daemon.

        Each of the interface dictionaries contains two lists of import:

        * client_list - a list of connected clients and a status update on them
        * routing_table - a list of all routes currently configured (likely one 
        per client)

        Each of these dictionaries also has a corresponding ``*_header`` 
        dictionary mapping header names to the index of that header within the 
        lists mentioned above.

        Returns:
            dict[str, dict[str, Any]]: A dictionary containing a detailed 
                breakdown of the VPN status
        """
        return self._RpcClient.GetVPNStatus()

    
    def VpnSummary(self) -> dict:
        """Get a summary of the number of clients connected to the VPN

        Returns:
            dict[str, int]: A dictionary with a single key which is 
                ``"n_clients"`` and whose value is the number of clients 
                connected to the VPN
        """
        return self._RpcClient.GetVPNSummary()
    