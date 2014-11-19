#!/usr/bin/env escript
%%! -pa ebin

-module(testproxy).
-compile(export_all).

-define(DEBUG(Format, Args), io:format(Format ++ "~n", Args)).

%% -define(DEFAULT_PROXY_ADDRESS, "183.90.187.93:1080").
%% -define(DEFAULT_PROXY_ADDRESS, "124.42.127.221:1080").
-define(DEFAULT_PROXY_ADDRESS, "127.0.0.1:1080").

-define(CONNECT_DEST_ADDRESS, {127, 0, 0, 1}).
-define(CONNECT_DEST_PORT, 32320).

-define(BIND_FROM_ADDRESS, {192,168,1,189}).
-define(BIND_FROM_PORT, 20).
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
%%   test_connect(Address, Port).
  test_bind(Address, Port).
%%   test_udp_associate(Address, Port).


negotiate_auth_method(Address, Port) ->
  {ok, Socket} = gen_tcp:connect(Address, Port, [binary, {active, false}, {nodelay, true}]),
  ?DEBUG("SENDING: auth method request (no_auth)", []),
  ok = gen_tcp:send(Socket, socks5:auth_method_selection_request([no_auth])),
  Expected = socks5:auth_method_selection_reply(no_auth),
  ?DEBUG("RECVING: auth method reply", []),
  {ok, Expected} = gen_tcp:recv(Socket, byte_size(Expected)),
  Socket.

test_connect(Address, Port) ->
  ?DEBUG("=== SOCKS5 CONNECT method test", []),
  Socket = negotiate_auth_method(Address, Port),
  {_, Ref} = erlang:spawn_monitor(fun() ->
    {ok, ServerSocket} = gen_tcp:listen(?CONNECT_DEST_PORT, [binary, {reuseaddr, true}, {active, false}, {nodelay, true}]),
    {ok, ClientSocket} = gen_tcp:accept(ServerSocket),
    {ok, Res} = gen_tcp:recv(ClientSocket, byte_size(?WHAT_TO_SEND)),
    ?DEBUG("RECVED : SOCKS5 proxy tunnel => ~p", [Res]),
    gen_tcp:close(ClientSocket),
    gen_tcp:close(ServerSocket)
  end),
  ?DEBUG("SENDING: request, connect: ~p:~p", [inet:ntoa(?CONNECT_DEST_ADDRESS), ?CONNECT_DEST_PORT]),
  gen_tcp:send(Socket, socks5:request(connect, ?CONNECT_DEST_ADDRESS, ?CONNECT_DEST_PORT)),
  {ok, Reply} = socks5:recv_reply(Socket),
  ?DEBUG("RECVED : reply ~p", [Reply]),
  ?DEBUG("SENDING: ~p => SOCKS5 proxy tunnel", [?WHAT_TO_SEND]),
  ok = gen_tcp:send(Socket, ?WHAT_TO_SEND),
  receive
    {'DOWN', Ref, process, _Pid, _Reason} -> ok
  end,
  ?DEBUG("CONNECT: OK", []).

test_bind(Address, Port) ->
  ?DEBUG("=== SOCKS5 BIND method test", []),
  Socket = negotiate_auth_method(Address, Port),
  ?DEBUG("SENDING: request, bind: ~p:~p", [inet:ntoa(?BIND_FROM_ADDRESS), ?BIND_FROM_PORT]),
  gen_tcp:send(Socket, socks5:request(bind, ?BIND_FROM_ADDRESS, ?BIND_FROM_PORT)),
  {ok, Reply} = socks5:recv_reply(Socket),
  ?DEBUG("RECVED : reply ~p", [Reply]),
  {succeeded, {_Type, ServerAddress}, ServerPort} = Reply,
  Slave = erlang:spawn(fun() ->
    {ok, ClientSocket} = gen_tcp:connect(ServerAddress, ServerPort, [binary, {port, ?BIND_FROM_PORT}, {reuseaddr, true}, {active, false}, {nodelay, true}]),
    ?DEBUG("SENDING: ~p => SOCKS5 proxy tunnel", [?WHAT_TO_SEND]),
    ok = gen_tcp:send(ClientSocket, ?WHAT_TO_SEND),
    receive
      you_can_exit -> ok
    end,
    gen_tcp:close(ClientSocket)
  end),
  {ok, Reply2} = socks5:recv_reply(Socket),
  ?DEBUG("RECVED : reply ~p", [Reply2]),
  {ok, Res} = gen_tcp:recv(Socket, byte_size(?WHAT_TO_SEND)),
  Slave ! you_can_exit,
  ?DEBUG("RECVED : SOCKS5 proxy tunnel => ~p", [Res]),
  ?DEBUG("BIND   : OK", []).

test_udp_associate(Address, Port) ->
  ?DEBUG("=== SOCKS5 UDP ASSOCIATE method test", []),
  ?DEBUG("U ASSOC: OK", []).

