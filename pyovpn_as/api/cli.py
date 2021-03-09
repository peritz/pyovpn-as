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
