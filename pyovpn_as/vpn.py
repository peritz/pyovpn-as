import ipaddress
from datetime import datetime
from typing import Any

from pyovpn_as.api import cli


class ClientStatus:
    """Represents the status of a given VPN client connected to the server

    Attributes:
        connected_since (datetime): When the client connected to the server
        username (str): Username of the connected client
        common_name (str): Common name of the certificate used to connect
        bytes_received (int): The bytes received from the client since 
            connecting
        bytes_send (int): The bytes send to the client since connecting
        virtual_address (IPv4Address): The virtual IPv4 address of the 
            connected client
        virtual_ipv6_address (IPv6Address): The virtual IPv6 address, or None 
            if the client has not been assigned one.
        real_address (str): The source IP address and port of the client 
            connection
        client_id (int): ID of the client connection
        peer_id (int): TODO define
    
    Args:
        attributes (list[str]): The list of attributes associated with a client 
            connections
        headers (dict[str, int]): A dictionary mapping header names to index in 
            the attributes list
    """
    def __init__(self, attributes: list, headers: dict):
        self.connected_since = datetime.fromtimestamp(attributes[
            headers['Connected Since (time_t)']
        ])
        self.username = attributes[
            headers['Username']
        ]
        self.common_name = attributes[
            headers['Common Name']
        ]
        self.bytes_received = int(attributes[
            headers['Bytes Received']
        ])
        self.bytes_sent = int(attributes[
            headers['Bytes Sent']
        ])
        self.virtual_address = ipaddress.ip_address(
            attributes[headers['Virtual Address']]
        )
        vipv6 = attributes[headers['Virtual IPv6 Address']]
        if vipv6 == '':
            self.virtual_ipv6_address = None
        else:
            self.virtual_ipv6_address = ipaddress.ip_address(vipv6)
        self.real_address = attributes[
            headers['Real Address']
        ]
        self.client_id = int(attributes[
            headers['Client ID']
        ])
        self.peer_id = int(attributes[
            headers['Peer ID']
        ])


class VPNStatus:
    """Represents the status of a given VPN interface

    We can get these connections from the sacli.VPNStatus() method. We access 
    the client_list key/value pair of the openvpn_X dictionaries and gather the 
    statistics from these dictionaries.

    Each openvpn_X dictionary will have a dictionary defining the headers for 
    the client_list lists and will look something like this::

        "client_list_header": {
            "Connected Since": 6,
            "Username": 8,
            "Common Name": 0,
            "Bytes Received": 4,
            "Virtual Address": 2,
            "Bytes Sent": 5,
            "Virtual IPv6 Address": 3,
            "Client ID": 9,
            "Connected Since (time_t)": 7,
            "Real Address": 1,
            "Peer ID": 10
        }
    
    The above indicates that the Common Name (of the certificate used to 
    connect) is in position 0 of each of the below lists::

        "client_list": [
            [
                "Example_Username",
                "1.1.1.1:55555",
                "172.27.228.2",
                "",
                "143313",
                "2727656",
                "Tue May  4 13:54:03 2021",
                "1620136443",
                "Example_Username",
                "0",
                "0"
            ]
        ]

    Attributes:
        interface_name (str): The name of the VPN daemon this status refers to
        connected_clients (list[ClientStatus]): List of clients connected to 
            the VPN

    Args:
        daemon_name (str): The name of the daemon the status refers to. 
            Normally this will be a name of the form ``openvpn_X``
        connection_summary (dict[str, Any]): A dictionary representing the 
            status of connections of a given VPN interface

    Raises:
        TypeError: if the connection_summary is not a dictionary
    """
    def __init__(self, daemon_name: str, connection_summary: dict):
        if not isinstance(connection_summary, dict):
            raise TypeError(
                f"Expected 'dict' for arg 'connection_summary', got "
                f"'{type(connection_summary)}'"
            )
        if not isinstance(daemon_name, str):
            raise TypeError(
                f"Expected 'str' for arg 'daemon_name', got "
                f"'{type(daemon_name)}'"
            )
        
        self.daemon_name = daemon_name

        headers = connection_summary['client_list_headers']
        self.connected_clients = [
            ClientStatus(attrs, headers) 
            for attrs in connection_summary['client_list']
        ]


class VpnOperations:
    """This class provides methods to monitor the status and alter the configuration of the VPN Daemon service

    Args:
        sacli (RemoteSacli): The client used to communicate with the server
    """
    def __init__(self, sacli: cli.RemoteSacli):
        if not isinstance(sacli, cli.RemoteSacli):
            raise TypeError(
                f"Expected 'RemoteSacli' for arg 'sacli', got '{type(sacli)}'"
            )
        self._sacli = sacli

    
    @property
    def status(self) -> list:
        """list[VpnStatus]: The detailed status of connections to the VPN 
        daemons
        """
        status_dict = self._sacli.GetVpnStatus()
        return [
            VPNStatus(daemon, status)
            for daemon, status 
            in status_dict
        ]
