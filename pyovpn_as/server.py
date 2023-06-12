"""This module provides the class used to perform operations on the server and 
its configuration. It will allow us to start, stop, reset, configure, and query 
the server's internal services
"""
import logging
from datetime import datetime

from pyovpn_as.api import cli

logger = logging.getLogger(__name__)


class ServerOperations:
    """Represents the operations we can perform on the server and its internal 
    services.

    This class shouldn't be instantiated directly, and instead you should
    access it via AccessServerManagementClient.server.

    Args:
        sacli (cli.RemoteSacli): The client we use to communicate with the
            server
    """
    def __init__(self, sacli: cli.RemoteSacli):
        if not isinstance(sacli, cli.RemoteSacli):
            raise TypeError(
                f"Expected 'RemoteSacli' for arg 'sacli', got '{type(sacli)}'"
            )
        self._sacli = sacli

    
    @property
    def version(self) -> str:
        """str: Version of the server we are communicating with
        """
        return self._sacli.Version()

    
    @property
    def last_restart_time(self) -> datetime:
        """datetime: The date and time the server's internal services were last 
        restarted
        """
        status = self._sacli.Status()
        return datetime.strptime(
            status.get('last_restarted'),
            '%a %b %d %H:%M:%S %Y'
        )
