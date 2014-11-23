#!/usr/bin/env escript
%%! -pa ebin

-module(acceptence).
-compile(export_all).

-define(DEBUG(Format, Args), io:format(Format ++ "~n", Args)).

%% -define(DEFAULT_PROXY_ADDRESS, "183.90.187.93:1080").
%% -define(DEFAULT_PROXY_ADDRESS, "124.42.127.221:1080").
-define(DEFAULT_PROXY_ADDRESS, "127.0.0.1:1080").

-define(WHAT_TO_SEND, <<"hello exante">>).


parse_args(AddressPort) ->
  [A, Port] = string:tokens(AddressPort, ":"),
  {ok, Address} = inet:parse_ipv4_address(A),
  {Address, list_to_integer(Port)}.

main([]) ->
  main([?DEFAULT_PROXY_ADDRESS]);

main([AddressPort]) when is_list(AddressPort) ->
  {Address, Port} = parse_args(AddressPort),
  ?DEBUG("connecting to ~p", [AddressPort]),
  test_connect(Address, Port, {0,0,0,0,0,0,0,1}, 17332),
  test_connect(Address, Port, {127, 0, 0, 1}, 17333),
  test_connect(Address, Port, "localhost", 17333),
  test_bind(Address, Port, {127,0,0,1}, 17334),
  test_bind(Address, Port, {0,0,0,0,0,0,0,1}, 17335),
  test_bind(Address, Port, "localhost", 17336),
  test_udp_associate(Address, Port, {127, 0, 0, 1}, 17337),
  test_udp_associate(Address, Port, {0,0,0,0,0,0,0,1}, 17338),
  test_udp_associate(Address, Port, "localhost", 17339).

test_connect(Address, Port, DestAddress, DestPort) ->
  Socket = negotiate_auth_method(Address, Port),
  Master = self(),
  erlang:spawn_link(fun() ->
    Ipv4Address =
      case is_list(DestAddress) of
        false -> DestAddress;
        true -> {ok, A} = inet:getaddr(DestAddress, inet), A
      end,
    {ok, ServerSocket} = gen_tcp:listen(DestPort, [binary, {ip, Ipv4Address}, {reuseaddr, true}, {active, false}, {nodelay, true}]),
    Master ! proceed,
    {ok, ClientSocket} = gen_tcp:accept(ServerSocket),
    {ok, Res} = gen_tcp:recv(ClientSocket, byte_size(?WHAT_TO_SEND)),
    ?DEBUG("RECVED : SOCKS5 proxy tunnel => ~p", [Res]),
    gen_tcp:close(ClientSocket),
    gen_tcp:close(ServerSocket)
  end),
  receive proceed -> ok end,
  {succeeded, _} = request_proxy(Socket, connect, {DestAddress, DestPort}),
  ?DEBUG("SENDING: ~p => SOCKS5 proxy tunnel", [?WHAT_TO_SEND]),
  ok = gen_tcp:send(Socket, ?WHAT_TO_SEND),
  ?DEBUG("CONNECT: OK", []).

test_bind(Address, Port, DestAddress, DestPort) ->
  Socket = negotiate_auth_method(Address, Port),
  {succeeded, {ServerAddress, ServerPort}} = request_proxy(Socket, bind, {DestAddress, DestPort}),
  Slave = erlang:spawn_link(fun() ->
    Ipv4Address =
      case is_list(DestAddress) of
        false -> DestAddress;
        true -> {ok, A} = inet:getaddr(DestAddress, inet), A
      end,
    {ok, ClientSocket} = gen_tcp:connect(ServerAddress, ServerPort, [binary, {ip, Ipv4Address}, {port, DestPort}, {reuseaddr, true}, {active, false}, {nodelay, true}]),
    ?DEBUG("SENDING: ~p => SOCKS5 proxy tunnel", [?WHAT_TO_SEND]),
    ok = gen_tcp:send(ClientSocket, ?WHAT_TO_SEND),
    receive proceed -> ok end,
    gen_tcp:close(ClientSocket)
  end),
  {ok, {succeeded, _} = Reply2} = socks5:recv_reply(Socket),
  ?DEBUG("RECVED : reply ~p", [Reply2]),
  {ok, Res} = gen_tcp:recv(Socket, byte_size(?WHAT_TO_SEND)),
  Slave ! proceed,
  ?DEBUG("RECVED : SOCKS5 proxy tunnel => ~p", [Res]),
  ?DEBUG("BIND   : OK", []).

test_udp_associate(Address, Port, DestAddress, DestPort) ->
  Socket = negotiate_auth_method(Address, Port),
  {succeeded, {RelayAddress, RelayPort}} = request_proxy(Socket, udp_associate, {DestAddress, DestPort}),
  Master = self(),
  Ipv4Address =
    case is_list(DestAddress) of
      false -> DestAddress;
      true -> {ok, X} = inet:getaddr(DestAddress, inet), X
    end,
  erlang:spawn_link(fun() ->
    {ok, ServerSocket} = gen_udp:open(DestPort + 42, [binary, {ip, Ipv4Address}, {reuseaddr, true}, {active, false}]),
    Master ! proceed,
    {ok, {A, P, Res}} = gen_udp:recv(ServerSocket, 0),
    ?DEBUG("RECVED : SOCKS5 proxy tunnel => ~p", [Res]),
    ok = gen_udp:send(ServerSocket, A, P, Res),
    ?DEBUG("SENDING: ~p => SOCKS5 proxy tunnel", [Res]),
    gen_udp:close(ServerSocket)
  end),
  receive proceed -> ok end,

  {ok, RelaySocket} = gen_udp:open(0, [binary, {active, false}, {ip, Ipv4Address}, {port, DestPort}]),
  ok = gen_udp:send(RelaySocket, RelayAddress, RelayPort, socks5:udp_datagram(0, {DestAddress, DestPort + 42}, ?WHAT_TO_SEND)),
  {ok, _, _, _, Res} = socks5:recv_udp_datagram(RelaySocket),
  ?DEBUG("RECVED : SOCKS5 proxy tunnel => ~p", [Res]),
  ?DEBUG("U ASSOC: OK", []).


negotiate_auth_method(Address, Port) ->
  {ok, Socket} = gen_tcp:connect(Address, Port, [binary, {active, false}, {nodelay, true}]),
  ok = gen_tcp:send(Socket, socks5:auth_method_selection_request([no_auth])),
  Expected = socks5:auth_method_selection_reply(no_auth),
  {ok, Expected} = gen_tcp:recv(Socket, byte_size(Expected)),
  Socket.

request_proxy(Socket, Type, {DestAddr, DestPort}) ->
  ?DEBUG("=== ~s method test (~s)", [pp(Type), pp(DestAddr)]),
  Request = socks5:request(Type, {DestAddr, DestPort}),
  ?DEBUG("SENDING: request: ~p, ~s:~p)", [Type, pp_address(DestAddr), DestPort]),
  gen_tcp:send(Socket, Request),
  {ok, Reply} = socks5:recv_reply(Socket),
  ?DEBUG("RECVED : reply  : ~p", [Reply]),
  Reply.

pp(connect) -> "      CONNECT";
pp(bind) -> "         BIND";
pp(udp_associate) -> "UDP ASSOCIATE";
pp(Address) when is_list(Address) -> "domain name";
pp(Address) when is_tuple(Address) -> case tuple_size(Address) of 4 -> "IPv4"; 8 -> "IPv6" end.

pp_address(A) when is_list(A) -> A;
pp_address(A) when is_tuple(A) -> inet:ntoa(A).