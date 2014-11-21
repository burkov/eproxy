-module(eproxy_negotiation).
-author(alex_burkov).

-export([start_link/1, loop/2]).


start_link(Socket) when is_port(Socket)->
  (Pid = erlang:spawn_link(?MODULE, loop, [Socket, self()])) ! recv_auth_method_selection_request,
  Pid.

loop(Socket, Master) ->
  receive
    recv_auth_method_selection_request ->
      {ok, Methods} = socks5:recv_auth_method_selection_request(Socket),
      gen_fsm:send(Master, {auth_methods, Methods});
    {do_authentication, no_auth} ->
      gen_fsm:send(Master, authenticated);
    {do_authentication, _Method} ->
      gen_fsm:send(Master, {authentication_failure, auth_type_not_supported});
    recv_request ->
      {ok, Request} = socks5:recv_request(Socket),
      gen_fsm:send(Master, Request);
    stop ->
      exit(normal)
  end,
  loop(Socket, Master).


%% old() ->
%%   {ok, <<ProtocolVersion:8, Command:8, Reserved:8, AType:8>>} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
%%   CommandName = socks5:command(Command),
%%   AddressTypeName = socks5:address_type(AType),
%%   ?VALIDATE("client request",
%%     begin
%%       throw_if(ProtocolVersion =/= ?VERSION_SOCKS5, {unsupported_socks_version, ProtocolVersion}),
%%       throw_if(CommandName =:= invalid_command, {unsupported_command, CommandName}),
%%       warn_if(Reserved =/= ?RESERVED, "reserved =/= ~p", [?RESERVED]),
%%       throw_if(AddressTypeName =:= invalid_address_type, {unsupported_address_type, AddressTypeName})
%%     end
%%   ),
%%   lager:debug("got command '~p', fetching address type of '~p'", [CommandName, AddressTypeName]),
%%   Address =
%%     case AddressTypeName of
%%       ipv4 ->
%%         {ok, Binary} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
%%         list_to_tuple([X || <<X>> <= Binary]);
%%       ipv6 ->
%%         {ok, Binary} = gen_tcp:recv(Socket, 16, ?RECV_TIMEOUT_MS),
%%         list_to_tuple([X || <<X:16>> <= Binary]);
%%       domain_name ->
%%         {ok, Length} = gen_tcp:recv(Socket, 1, ?RECV_TIMEOUT_MS),
%%         {ok, DomainName} = gen_tcp:recv(Socket, Length, ?RECV_TIMEOUT_MS),
%%         DomainName
%%     end,
%%   lager:debug("address = ~p", [Address]);
%% Else ->
%% lager:warning("unknown command (~p), exiting", [Else])
