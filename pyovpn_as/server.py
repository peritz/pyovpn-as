"""This module provides the class used to perform operations on the server and 
its configuration. It will allow us to start, stop, reset, configure, and query 
the server's internal services
"""
import logging
from datetime import datetime

from pyovpn_as.api import client

logger = logging.getLogger(__name__)


class ServerOperations:
    """Represents the operations we can perform on the server and its internal 
    services.

    This class shouldn't be instantiated directly, and instead you should
    access it via AccessServerManagementClient.server.

    Args:
       _client (RestApiClient): The client we use to communicate with the
            server
    """
    def __init__(self, _client: client.RestApiClient):
        if not isinstance(_client, client.RestApiClient):
            raise TypeError(
                f"Expected 'RestApiClient' for arg '_client', got '{type(client)}'"
            )
        self._client = _client

    
    @property
    def version(self) -> str:
        """str: Version of the server we are communicating with
        """
        return self._client.get("/server/info")["version"]

    
    @property
    def last_restart_time(self) -> datetime:
        """datetime: The date and time the server's internal services were last 
        restarted
        """
        status = self._client.get("/server/status")
        return datetime.fromisoformat(status["last_restarted"])
