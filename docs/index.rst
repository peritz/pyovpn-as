.. pyovpn-as documentation master file, created by
   sphinx-quickstart on Thu Apr 15 09:56:59 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Python OpenVPN Access Server SDK
=====================================

A Python library built on XML-RPC that demystifies remote interaction with `OpenVPN Access Server`_.

OpenVPN Access Server provides an XML-RPC API that allows administrators to manage the server remotely and programatically. Unfortunately, OpenVPN explicitly provides this feature undocumented. This SDK provides a way to interact with this API, with helpful error messages, powerful functionality, and a clear explanation of what the hell you're looking at.

For support please email `ryanharrison.opensource@protonmail.com`_. Code is at https://github.com/ryanharrison554/pyovpn-as


Getting Started
---------------

Getting started is simple. First you must enable the XML-RPC feature on your access server. This can be done either through the web interface by navigating to ``Configurations -> Client Settings -> Enable Complete API`` or by setting it via the command line ``./sacli --key "xmlrpc.relay_level" --value 2 ConfigPut && ./sacli start``

Now we can start running commands::

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

**Note:** if you haven't yet installed a trusted SSL certificate on the server, you will need to provide the ``allow_untrusted=True`` parameter anytime you create a client.

Installation
------------

``pip install pyovpn-as``

How to Contribute
-----------------

There are three main ways to contribute to this project:

- Search for open issues or open your own issue for a bug or problem discovered in the codebase or the documentation
- Submit a pull request to merge a feature or fix into the master branch (more information on how to do that and what maintainers expect from your code can be found in the full documentation)
- Use this SDK to poke at OpenVPN Access Server to find additional functionality, or to clarify the functionality given here, then open an issue and tell us what you found and how we can improve

We don't accept monetary contributions, everything you see is free :)

License
-------

GPL license, see the `License`_


.. toctree::
   :maxdepth: 2
   :caption: Contents:


.. _OpenVPN Access Server: https://openvpn.net/access-server/
.. _ryanharrison.opensource@protonmail.com: ryanharrison.opensource@protonmail.com
.. _License: https://github.com/ryanharrison554/pyovpn-as/blob/master/LICENSE


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
