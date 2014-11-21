-module(eproxy_relay).
-author(alex_burkov).

-export([spawn_link/3, relay/3]).


spawn_link(Master, InSocket, OutSocket) ->
  erlang:spawn(?MODULE, relay, [Master, InSocket, OutSocket]).

relay(Master, InSocket, OutSocket) ->
  ok,
  relay(Master, InSocket, OutSocket).