"""This module provides functionality similar to that of the sacli tool in
   OpenVPN Access Servers.

Attributes:
    XML_RPC_VAL (TypeVar): The list of types that an XML-RPC parameter is
        allowed to be
"""

import logging
from datetime import datetime
from typing import TypeVar

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

class AccessServerClient:
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
        AccessServerBaseException: Something went wrong in connecting to the
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
    

    def UserPropPut(
        self,
        user: str,
        key: str,
        value: XML_RPC_VAL,
        noui: bool=False
    ) -> list[bool, dict]:
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
        tfilt: list[str]=None,
        pfilt: list[str]=None
    ) -> dict[str, dict[str, XML_RPC_VAL]]:
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
        return self._RpcClient.UserPropProfileMultiGet(tfilt, pfilt)

    def UserPropDel(
        self,
        user: str,
        key: str
    ) -> list[bool, dict]:
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

    def UserPropCount(self, tfilt: list[str]=None) -> int:
        """Count the number of profiles that exist by filtering on profile type

        Args:
            tfilt (list[str], optional): Profile type to filter by. Defaults to
                None.

        Returns:
            int: Number of profiles that match the given filter
        """
        return self._RpcClient.UserPropProfileCount(tfilt)

