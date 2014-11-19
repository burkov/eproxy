-module(socks5).
-author(alex_burkov).

-include("socks5.hrl").

-export([
  auth_method_selection_request/1,
  auth_method_selection_reply/1,
  request/3,
  reply/3,
  udp_datagram/4,
  auth_method/1,
  command/1,
  address_type/1,

  recv_reply/1
]).


-spec auth_method_selection_request([auth_method()]) -> binary().
%% @doc constructs cleint's auth method selection request
auth_method_selection_request(MethodNames) ->
  Methods = lists:usort([auth_method(M) || M <- MethodNames, is_atom(M)]),
  NMethods = length(Methods),
  <<?VERSION_SOCKS5, NMethods:8, (list_to_binary(Methods))/binary>>.

-spec auth_method_selection_reply(auth_method()) -> binary().
%% @doc constructs server's auth method selection reply
auth_method_selection_reply(Method) when is_atom(Method) ->
  <<?VERSION_SOCKS5, (auth_method(Method)):8>>.

-spec request(command(), inet:ip_address() | string(), inet:port_number()) -> binary().
%% @doc constructs client's request
request(Command, Address, Port) when is_atom(Command) ->
  <<?VERSION_SOCKS5, (command(Command)):8, ?RESERVED, (address_to_binary(Address))/binary, Port:16>>.

-spec reply(reply_code(), inet:ip_address() | string(), inet:port_number()) -> binary().
%% @doc constructs client's reply
reply(ReplyCode, Address, Port) when is_atom(ReplyCode) ->
  <<?VERSION_SOCKS5, (reply_code(ReplyCode)):8, ?RESERVED, (address_to_binary(Address))/binary, Port:16>>.

-spec udp_datagram(pos_integer(), inet:ip_address() | string(), inet:port_number(), binary()) -> binary().
%% @doc wraps UDP datagrap with a header
udp_datagram(FragmentNo, Address, Port, Data) ->
  <<?RESERVED, ?RESERVED, FragmentNo:8, (address_to_binary(Address))/binary, Port:16, Data/binary>>.

-spec address_to_binary(inet:ip_address() | string()) -> binary().
%% @doc converts address of given type into its coded representation
address_to_binary(Tuple) when is_tuple(Tuple) ->
  case tuple_size(Tuple) of
    4 -> <<?ADDRESS_TYPE_IPV4, (list_to_binary(tuple_to_list(Tuple)))/binary>>;
    8 -> <<?ADDRESS_TYPE_IPV6, <<<<X:16>> || X <- tuple_to_list(Tuple)>>/binary>>
  end;

address_to_binary(List) when is_list(List) ->
  case length(List) >= 16#ff of
    true -> throw(name_too_long);
    false -> <<?ADDRESS_TYPE_DOMAIN_NAME, (length(List)):8, (list_to_binary(List))/binary>>
  end.

-spec auth_method
    (pos_integer()) -> auth_method();
    (auth_method()) -> pos_integer().
%% @doc associates authorization method pre-coded value with its atomized name and vice versa
auth_method(?AUTH_METHOD_NO_AUTH) -> no_auth;
auth_method(?AUTH_METHOD_GSSAPI) -> gssapi;
auth_method(?AUTH_METHOD_PASSWORD) -> password;
auth_method(?NO_ACCEPTABLE_MATHODS) -> no_acceptable_methods;
auth_method(X) when X >= ?AUTH_METHOD_IANA_ASSIGNED_LOW, X =< ?AUTH_METHOD_IANA_ASSIGNED_HIGH -> iana_assigned;
auth_method(X) when is_integer(X) -> private_methods;
auth_method(no_auth) -> ?AUTH_METHOD_NO_AUTH;
auth_method(gssapi) -> ?AUTH_METHOD_GSSAPI;
auth_method(password) -> ?AUTH_METHOD_PASSWORD;
auth_method(no_acceptable_methods) -> ?NO_ACCEPTABLE_MATHODS.

-spec address_type
    (pos_integer()) -> address_type();
    (address_type()) -> pos_integer().
%% @doc associates address type pre-coded value with its atomized name and vice versa
address_type(?ADDRESS_TYPE_IPV4) -> ipv4;
address_type(?ADDRESS_TYPE_DOMAIN_NAME) -> domain_name;
address_type(?ADDRESS_TYPE_IPV6) -> ipv6;
address_type(X) when is_integer(X) -> invalid_address_type;
address_type(ipv4) -> ?ADDRESS_TYPE_IPV4;
address_type(domain_name) -> ?ADDRESS_TYPE_DOMAIN_NAME;
address_type(ipv6) -> ?ADDRESS_TYPE_IPV6.

-spec command
    (pos_integer()) -> command();
    (command()) -> pos_integer().
%% @doc associates command pre-coded value with its atomized name and vice versa
command(?COMMAND_CONNECT) -> connect;
command(?COMMAND_BIND) -> bind;
command(?COMMAND_UDP_ASSOCIATE) -> udp_associate;
command(X) when is_integer(X) -> invalid_command;
command(connect) -> ?COMMAND_CONNECT;
command(bind) -> ?COMMAND_BIND;
command(udp_associate) -> ?COMMAND_UDP_ASSOCIATE.

-spec reply_code
    (pos_integer()) -> reply_code();
    (reply_code()) -> pos_integer().
%% @doc associates reply code value with its atomized name and vice versa
reply_code(?REPLY_SUCCEEDED) -> succeeded;
reply_code(?REPLY_GENERAL_FAILURE) -> general_failure;
reply_code(?REPLY_CONNECTION_NO_ALLOWED_BY_RULESET) -> connection_not_allowed_by_ruleset;
reply_code(?REPLY_NETWORK_UNREACHABLE) -> network_unreachable;
reply_code(?REPLY_HOST_UNREACHABLE) -> host_unreachable;
reply_code(?REPLY_CONNECTION_REFUSED) -> connection_refused;
reply_code(?REPLY_TTL_EXPIRED) -> ttl_expired;
reply_code(?REPLY_COMMAND_NOT_SUPPORTED) -> command_not_supported;
reply_code(?REPLY_ADDRESS_TYPE_NOT_SUPPORTED) -> address_type_not_supported;
reply_code(X) when is_integer(X) -> unassigned;
reply_code(succeeded) -> ?REPLY_SUCCEEDED;
reply_code(general_failure) -> ?REPLY_GENERAL_FAILURE;
reply_code(connection_not_allowed_by_ruleset) -> ?REPLY_CONNECTION_NO_ALLOWED_BY_RULESET;
reply_code(network_unreachable) -> ?REPLY_NETWORK_UNREACHABLE;
reply_code(host_unreachable) -> ?REPLY_HOST_UNREACHABLE;
reply_code(connection_refused) -> ?REPLY_CONNECTION_REFUSED;
reply_code(ttl_expired) -> ?REPLY_TTL_EXPIRED;
reply_code(command_not_supported) -> ?REPLY_COMMAND_NOT_SUPPORTED;
reply_code(address_type_not_supported) -> ?REPLY_ADDRESS_TYPE_NOT_SUPPORTED.


-spec recv_reply(gen_tcp:socket()) -> {ok, {reply_code(), {address_type(), inet:ip_address()|string()}, inet:port_number()}} | {error, Reason :: any()}.
%% @doc receives socks5 reply from given passive socket. throw-safe.
recv_reply(Socket) ->
  try
    {ok, <<?VERSION_SOCKS5, ReplyCode, ?RESERVED, AType>>} = gen_tcp:recv(Socket, 4),
    Address = recv_address(Socket, AType),
    {ok, <<Port:16>>} = gen_tcp:recv(Socket, 2),
    {ok, {reply_code(ReplyCode), {address_type(AType), Address}, Port}}
  catch T:E -> {error, {T, E}}
  end.

recv_address(Socket, ?ADDRESS_TYPE_IPV4) ->
  try
    {ok, A} = gen_tcp:recv(Socket, 4),
    list_to_tuple(binary_to_list(A))
  catch T:E -> {error, {T, E}}
  end;

recv_address(Socket, ?ADDRESS_TYPE_IPV6) ->
  try
    {ok, A} = gen_tcp:recv(Socket, 16),
    list_to_tuple([X || <<X:16>> <= A])
  catch T:E -> {error, {T, E}}
  end;

recv_address(Socket, ?ADDRESS_TYPE_DOMAIN_NAME) ->
  try
    {ok, <<Len>>} = gen_tcp:recv(Socket, 1),
    {ok, Name} = gen_tcp:recv(Socket, Len),
    Name
  catch T:E -> {error, {T, E}}
  end.


