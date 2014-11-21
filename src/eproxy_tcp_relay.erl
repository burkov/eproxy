-module(eproxy_tcp_relay).
-author(alex_burkov).

-export([spawn_link/2, relay/3]).


spawn_link(InSocket, OutSocket) ->
  erlang:spawn(?MODULE, relay, [self(), InSocket, OutSocket]).

relay(Master, InSocket, OutSocket) ->
  ok,
  relay(Master, InSocket, OutSocket).