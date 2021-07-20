"""This module provides the UserOperations class which allows us to define 
high-level functionality for managing groups on the sacli server
"""
import logging
from typing import Union

from . import exceptions, utils
from .profile import GroupProfile, ProfileOperations

logger = logging.getLogger(__name__)


class GroupOperations(ProfileOperations):
    """This class represents the operations we can perform on groups.

    This class shouldn't be instantiated directly, but should instead be 
    created by referencing the ``groups`` attribute on 
    AccessServerManagementClient objects.

    This class inherits the methods and attributes from ProfileOperations.

    Args:
        sacli (cli.RemoteSacli): The client we use to communicate with the
            server
    """
    @utils.debug_log_call()
    def get_group(
        self, group: Union[str, GroupProfile]
    ) -> GroupProfile:
        """Retrieves a group from the server using the specified client

        Args:
            group (Union[str, GroupProfile]): The group to fetch

        Raises:
            AccessServerProfileNotFoundError: Profile does not exist
            AccessServerProfileExistsError: groupname provided is the name of a
                user, not a group

        Returns:
            GroupProfile: A profile representing the fetched group
        """
        groupname = str(group)

        profile = self._get_profile(groupname)
        
        if profile.type == 'group':
            raise exceptions.AccessServerProfileExistsError(
                f'"{groupname}" is the name of a group, not a group'
            )
        else:
            return GroupProfile(groupname, profile)


    @utils.debug_log_call()
    def create_group(
        self, group: Union[str, GroupProfile], **kwargs
    ) -> GroupProfile:
        """Create a new group from a given profile or for the given name

        Args:
            group (Union[str, GroupProfile]): The name of the group, or a 
                profile representing the group to create

        Raises:
            AccessServerProfileExistsError: group_name provided already exists 
                as either a user or a group

        Returns:
            GroupProfile: The profile we have just created
        """
        # Merge properties into one profile and create the profile
        group_name = str(group)
        properties = kwargs
        properties['group_declare'] = 'true'
        if isinstance(group, GroupProfile):
            new_profile = self._create_profile(group_name, group, **properties)
        else:
            new_profile = self._create_profile(group_name, **properties)
        
        return GroupProfile(group_name, new_profile)


    @utils.debug_log_call()
    def delete_group(
        self, group: Union[str, GroupProfile]
    ):
        """Delete a given group from the server

        If users belong to this group, they will no longer inherit any 
        properties from the group and will not be connected into this group's 
        subnets. Essentially, any users belonging to this group will default to 
        the ``__DEFAULT__`` group again.

        TODO Add safe argument
        TODO Add cascade argument

        Args:
            group (Union[str, GroupProfile]): Group to delete

        Raises:
            AccessServerProfileNotFoundError: group does not exist on the 
                server.
            AccessServerProfileExistsError: group provided is the name of a
                group, not a user
            AccessServerProfileDeleteError: Could not delete the profile for
                an unknown reason
        """
        group_name = str(group)
        self.get_group(group_name)
        self._delete_profile(group_name)


    @utils.debug_log_call()
    def ban_group(
        self,
        group: Union[str, GroupProfile]
    ) -> None:
        """Ban a group from connecting to the VPN

        Args:
            group (Union[str, GroupProfile]): The group to ban from the VPN

        Raises:
            AccessServerProfileNotFoundError: group does not exist on the 
                server.
            AccessServerProfileExistsError: group provided is the name of a
                group, not a user
        """
        group_name = str(group)
        self.get_group(group_name)
        self._ban_profile(group_name)

    
    @utils.debug_log_call()
    def list_groups(self) -> list:
        """Lists all groups present on the server

        Returns:
            list[GroupProfile]: A list of all group profiles on the target 
                server
        """
        profile_dict = self._sacli.UserPropGet(
            tfilt=[GroupProfile.GROUP,]
        )
        return [
            GroupProfile(group, **props) 
            for group, props in profile_dict.items()
        ]
