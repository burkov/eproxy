-author(dhcb78).

-type auth_method() :: no_auth | gssapi | password | iana_reserved | private_methods | none.
-type command() :: connect | bind | udp_associate | invalid_command.
-type address_type() :: ipv4 | domain_name | ipv6 | invalid_address_type.

