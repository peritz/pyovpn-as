import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pyovpn_as.api import client


@dataclass(kw_only=True)
class ClientStatus:
    """Represents the status of a given VPN client connected to the server

    Attributes:
        daemon_id (str): ID of the daemon the client has connected to
        client_id (int): ID of the client which has connected
        bytes_sent (int): Bytes sent
        bytes_received (int): Bytes receive
        commonname (str): Common name the client uses in the certificate
        username (str): Username of the connected user
        connected_since (str): ISO datetime of when the client connected
        datachannel_cipher (str): Cipher being used to secure the data channel
        real_address (str): Real address the client connected from
        virtual_ipv4_address (str): Virtual IPv4 of the client
        virtual_ipv6_address (str): Virtual IPv6 address of the client
    """

    daemon_id: str
    client_id: int
    bytes_sent: int = None
    bytes_received: int = None
    common_name: str = None
    username: str = None
    connected_since: str = None
    datachannel_cipher: str = None
    real_address: str = None
    virtual_ipv4_address: str = None
    virtual_ipv6_address: str = None


class VpnOperations:
    """This class provides methods to monitor the status and alter the configuration of the VPN Daemon service

    Args:
        _client (RestApiClient): The client used to communicate with the server
    """

    def __init__(self, _client: client.RestApiClient):
        if not isinstance(_client, client.RestApiClient):
            raise TypeError(
                f"Expected 'RestApiClient' for arg '_client', got '{type(client)}'"
            )
        self._client = _client

    @property
    def status(self) -> list:
        """list[ClientStatus]: The detailed status of connections to the VPN
        daemons
        """
        return [
            ClientStatus(**vpn_client)
            for vpn_client in self._client.get("/vpn/status")["vpn_clients"]
        ]
