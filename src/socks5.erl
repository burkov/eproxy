-module(socks5).
-author(alex_burkov).

-include("socks5.hrl").

-export([
  auth_method_selection_request/1,
  auth_method_selection_reply/1,
  request/2,
  reply/2,
  udp_datagram/3,
  auth_method/1,
  command/1,
  address_type/1,

  send_auth_method_selection_reply/2,
  send_auth_method_selection_reject/1,
  send_reply/2,
  send_reply/3,

  recv_auth_method_selection_request/1,
  recv_request/1,
  recv_reply/1,
  recv_udp_datagram/1
]).


-define(RECV_TIMEOUT_MS, 1000).

-spec auth_method_selection_request([auth_method()]) -> binary().
%% @doc constructs cleint's auth method selection request
auth_method_selection_request(MethodNames) when is_list(MethodNames) ->
  Methods = lists:usort([auth_method(M) || M <- MethodNames, is_atom(M)]),
  NMethods = length(Methods),
  <<?VERSION_SOCKS5, NMethods:8, (list_to_binary(Methods))/binary>>.

-spec auth_method_selection_reply(auth_method()) -> binary().
%% @doc constructs server's auth method selection reply
auth_method_selection_reply(Method) when is_atom(Method) ->
  <<?VERSION_SOCKS5, (auth_method(Method)):8>>.

-spec request(command(), address_and_port()) -> binary().
%% @doc constructs client's request
request(Command, {Address, Port}) when is_atom(Command) ->
  <<?VERSION_SOCKS5, (command(Command)):8, ?RESERVED, (address_port_to_binary({Address, Port}))/binary>>.

-spec reply(reply_code(), address_and_port()) -> binary().
%% @doc constructs client's reply
reply(ReplyCode, {Address, Port}) when is_atom(ReplyCode) ->
  <<?VERSION_SOCKS5, (reply_code(ReplyCode)):8, ?RESERVED, (address_port_to_binary({Address, Port}))/binary>>.

-spec udp_datagram(byte(), address_and_port(), binary()) -> binary().
%% @doc wraps UDP datagrap with a header
udp_datagram(FragmentNo, {Address, Port}, Data) ->
  <<?RESERVED:16, FragmentNo:8, (address_port_to_binary({Address, Port}))/binary, Data/binary>>.

-spec address_port_to_binary(address_and_port()) -> binary().
%% @doc converts address and port into their coded representation
address_port_to_binary({Address, Port}) when is_tuple(Address); is_list(Address) ->
  <<(address_to_binary(Address))/binary, Port:16>>.

-spec address_to_binary(inet:ip_address() | string()) -> binary().
%% @doc converts address into its coded representation
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
    (byte()) -> auth_method();
    (auth_method()) -> byte().
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
    (byte()) -> address_type();
    (address_type()) -> byte().
%% @doc associates address type pre-coded value with its atomized name and vice versa
address_type(?ADDRESS_TYPE_IPV4) -> ipv4;
address_type(?ADDRESS_TYPE_DOMAIN_NAME) -> domain_name;
address_type(?ADDRESS_TYPE_IPV6) -> ipv6;
address_type(X) when is_integer(X) -> invalid_address_type;
address_type(ipv4) -> ?ADDRESS_TYPE_IPV4;
address_type(domain_name) -> ?ADDRESS_TYPE_DOMAIN_NAME;
address_type(ipv6) -> ?ADDRESS_TYPE_IPV6.

-spec command
    (byte()) -> command();
    (command()) -> byte().
%% @doc associates command pre-coded value with its atomized name and vice versa
command(?COMMAND_CONNECT) -> connect;
command(?COMMAND_BIND) -> bind;
command(?COMMAND_UDP_ASSOCIATE) -> udp_associate;
command(X) when is_integer(X) -> invalid_command;
command(connect) -> ?COMMAND_CONNECT;
command(bind) -> ?COMMAND_BIND;
command(udp_associate) -> ?COMMAND_UDP_ASSOCIATE.

-spec reply_code
    (byte()) -> reply_code();
    (reply_code()) -> byte().
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


-spec send_reply(gen_tcp:socket(), reply_code()) -> ok | {error, Reason :: any}.
send_reply(Socket, ErrorCode) when is_atom(ErrorCode) ->
  try gen_tcp:send(Socket, <<?VERSION_SOCKS5, (reply_code(ErrorCode)):8, ?RESERVED>>)
  catch _:Reason -> {error, Reason} end.

send_reply(Socket, Code, {_, _} = AP) when is_atom(Code) ->
  try gen_tcp:send(Socket, <<?VERSION_SOCKS5, (reply_code(Code)):8, ?RESERVED, (address_port_to_binary(AP))/binary>>)
  catch _:Reason -> {error, Reason} end.

send_auth_method_selection_reply(Socket, Method) when is_atom(Method) ->
  try gen_tcp:send(Socket, <<?VERSION_SOCKS5, (auth_method(Method)):8>>)
  catch _:Reason -> {error, Reason} end.

send_auth_method_selection_reject(Socket) ->
  send_auth_method_selection_reply(Socket, no_acceptable_methods).

recv_auth_method_selection_request(Socket) ->
  try
    {ok, <<?VERSION_SOCKS5, NMethods>>} = gen_tcp:recv(Socket, 2, ?RECV_TIMEOUT_MS),
    {ok, Methods} = gen_tcp:recv(Socket, NMethods, ?RECV_TIMEOUT_MS),
    {ok, lists:usort([auth_method(M) || <<M>> <= Methods])}
  catch _:Reason -> {error, Reason} end.

-spec recv_reply(gen_tcp:socket()) -> {ok, {reply_code(), address_and_port()}} | {error, Reason :: any()}.
%% @doc receives socks5 reply from given passive socket. throw-safe.
recv_reply(Socket) ->
  try
    {ok, <<?VERSION_SOCKS5, ReplyCode, ?RESERVED, AType>>} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
    {ok, AP} = recv_address_port(Socket, AType),
    {ok, {reply_code(ReplyCode), AP}}
  catch _:Reason -> {error, Reason} end.

recv_request(Socket) ->
  try
    {ok, <<?VERSION_SOCKS5, Command, ?RESERVED, AType>>} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
    {ok, AP} = recv_address_port(Socket, AType),
    {ok, {command(Command), AP}}
  catch _:Reason -> {error, Reason} end.

-spec recv_address_port(gen_tcp:socket(), byte()) -> {ok, address_and_port()} | {error, invalid_addess_type}.
%% @doc receives socks5 address and port from given passive socket.
recv_address_port(Socket, Type) ->
  case recv_address(Socket, Type) of
    {ok, Address} ->
      {ok, <<Port:16>>} = gen_tcp:recv(Socket, 2, ?RECV_TIMEOUT_MS),
      {ok, {Address, Port}};
    {error, _Reason} -> {error, invalid_address_type}
  end.

-spec recv_address(gen_tcp:socket(), byte()) -> {ok, inet:ip_address() | string()} | {error, Reason :: any()}.
%% @doc receives socks5 address from given passive socket.
recv_address(Socket, ?ADDRESS_TYPE_IPV4) ->
  {ok, A} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
  {ok, list_to_tuple(binary_to_list(A))};

recv_address(Socket, ?ADDRESS_TYPE_IPV6) ->
  {ok, A} = gen_tcp:recv(Socket, 16, ?RECV_TIMEOUT_MS),
  {ok, list_to_tuple([X || <<X:16>> <= A])};

recv_address(Socket, ?ADDRESS_TYPE_DOMAIN_NAME) ->
  {ok, <<Len>>} = gen_tcp:recv(Socket, 1, ?RECV_TIMEOUT_MS),
  {ok, Name} = gen_tcp:recv(Socket, Len, ?RECV_TIMEOUT_MS),
  {ok, binary_to_list(Name)};

recv_address(_Socket, _) ->
  {error, invalid_address_type}.

-spec recv_udp_datagram(gen_tcp:socket()) ->
  {ok, Relay :: address_and_port(), Source :: address_and_port(), FragmentNo :: fragment_no(), Data :: binary()} | {error, Reason :: any()}.
%% @doc receives socks5 udp datagram from given passive socket. throw-safe.
recv_udp_datagram(Socket) ->
  try
    {ok, {RelayAddress, RelayPort, <<?RESERVED:16, Fragment:8, AType:8, Rest/binary>>}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT_MS),
    case AType of
      ?ADDRESS_TYPE_DOMAIN_NAME ->
        <<Len:8, Rest2/binary>> = Rest,
        <<Name:Len, Port:16, OriginalData/binary>> = Rest2,
        {ok, {RelayAddress, RelayPort}, {Name, Port}, Fragment, OriginalData};
      ?ADDRESS_TYPE_IPV4 ->
        <<IPv4Addr:32, Port:16, OriginalData/binary>> = Rest,
        {ok, {RelayAddress, RelayPort}, {IPv4Addr, Port}, Fragment, OriginalData};
      ?ADDRESS_TYPE_IPV6 ->
        <<IPv6Addr:(8 * 16), Port:16, OriginalData/binary>> = Rest,
        {ok, {RelayAddress, RelayPort}, {IPv6Addr, Port}, Fragment, OriginalData}
    end
  catch Reason -> {error, Reason} end.

