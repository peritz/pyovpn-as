# Python OpenVPN Access Server SDK

A Python library built on XML-RPC that demystifies remote interaction with OpenVPN Access Server

OpenVPN Access Server provides an XML-RPC API that allows administrators to manage the server remotely and programatically. Unfortunately, OpenVPN explicitly provides this feature undocumented. This SDK provides a way to interact with this API, with helpful error messages, powerful functionality, and a clear explanation of what the hell you're looking at.

For support please email [peritz@pardonmynoot.com](mailto:peritz@pardonmynoot.com). Code is at https://github.com/peritz/pyovpn-as

## Getting Started

Getting started is simple. First you must enable the XML-RPC feature on your access server. This can be done either through the web interface by navigating to `Configurations -> Client Settings -> Enable Complete API` or by setting it via the command line `./sacli --key "xmlrpc.relay_level" --value 2 ConfigPut`

Now we can start running commands:

```python
>>> from pyovpn_as import client

>>> mgmt_client = client.from_args('https://ovpn.example.org/RPC2/', 'openvpn', 'P4ssw0rd!!!!')

>>> new_user = mgmt_client.users.create_new_user('newuser', 'P4ssw0rd123£', prop_superuser=True)

>>> new_user.type

"user_connect"

>>> new_user.is_admin

True

>>> mgmt_client.users.delete_user(as_client, '404')
Traceback (most recent call last):   
  File "<stdin>", line 1, in <module>
AccessServerProfileNotFoundError: User "404" does not exist
```

## Installation

`pip install pyovpn-as`

## How to Contribute

There are three main ways to contribute to this project:

- Search for open issues or open your own issue for a bug or problem discovered in the codebase or the documentation
- Submit a pull request to merge a feature or fix into the master branch (more information on how to do that and what maintainers expect from your code can be found in the full documentation)
- Use this SDK to poke at OpenVPN Access Server to find additional functionality, or to clarify the functionality given here, then open an issue and tell us what you found and how we can improve

We don't accept monetary contributions, everything you see is free :)

## License

GPL license, see the [License](./LICENSE)

