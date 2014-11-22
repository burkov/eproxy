-module(eproxy_udp_relay).
-author(alex_burkov).

-export([spawn_link/2, spawn_link/3, loop/4]).


spawn_link(InUdpSocket, OutUdpSocket, {SrcAddress, SrcPort}) ->
  erlang:spawn_link(?MODULE, loop, [self(), InUdpSocket, OutUdpSocket, {SrcAddress, SrcPort}]).

spawn_link(InUdpSocket, OutUdpSocket) ->
  eproxy_udp_relay:spawn_link(InUdpSocket, OutUdpSocket, {any, any}).


loop(Master, InSocket, OutSocket, {SrcAddress, SrcPort}) ->
  case gen_udp:recv(InSocket, 0) of
    {error, Reason} ->
      ok;
    {ok, {Address, Port, Packet}} ->
      ok;
  end,
  ok,
  loop(Master, InSocket, OutSocket, {SrcAddress, SrcPort}).
