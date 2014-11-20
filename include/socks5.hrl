-author(dhcb78).

-define(VERSION_SOCKS5, 5).

-define(RESERVED, 16#00).

-define(AUTH_METHOD_NO_AUTH, 0).
-define(AUTH_METHOD_GSSAPI, 1).
-define(AUTH_METHOD_PASSWORD, 2).
-define(AUTH_METHOD_IANA_ASSIGNED_LOW, 3).
-define(AUTH_METHOD_IANA_ASSIGNED_HIGH, 16#7f).
-define(AUTH_METHOD_PRIVATE_METHODS_LOW, 16#80).
-define(AUTH_METHOD_PRIVATE_METHODS_HIGH, 16#fe).
-define(NO_ACCEPTABLE_MATHODS, 16#ff).

-define(COMMAND_CONNECT, 1).
-define(COMMAND_BIND, 2).
-define(COMMAND_UDP_ASSOCIATE, 3).

-define(ADDRESS_TYPE_IPV4, 1).
-define(ADDRESS_TYPE_DOMAIN_NAME, 3).
-define(ADDRESS_TYPE_IPV6, 4).

-define(REPLY_SUCCEEDED, 0).
-define(REPLY_GENERAL_FAILURE, 1).
-define(REPLY_CONNECTION_NO_ALLOWED_BY_RULESET, 2).
-define(REPLY_NETWORK_UNREACHABLE, 3).
-define(REPLY_HOST_UNREACHABLE, 4).
-define(REPLY_CONNECTION_REFUSED, 5).
-define(REPLY_TTL_EXPIRED, 6).
-define(REPLY_COMMAND_NOT_SUPPORTED, 7).
-define(REPLY_ADDRESS_TYPE_NOT_SUPPORTED, 8).
-define(REPLT_UNASSIGNED_LOW, 9).
-define(REPLT_UNASSIGNED_HIGH, 16#ff).


-type address_and_port() :: {inet:ip_address() | string(), inet:port_number()}.
-type auth_method() :: no_auth | gssapi | password | iana_assigned | private_methods | no_acceptable_methods.
-type command() :: connect | bind | udp_associate | invalid_command.
-type address_type() :: ipv4 | domain_name | ipv6 | invalid_address_type.
-type reply_code() :: succeeded | general_failure | connection_not_allowed_by_ruleset | network_unreachable | host_unreachable |
connection_refused | ttl_expired | command_not_supported | address_type_not_supported | unassigned.
-type fragment_no() :: byte().