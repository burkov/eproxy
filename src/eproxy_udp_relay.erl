-module(eproxy_udp_relay).
-author(alex_burkov).

-export([spawn_link/2, loop/4]).


spawn_link(InUdpSocket, OutUdpSocket, {SrcAddress, SrcPort}) ->
  erlang:spawn_link(?MODULE, loop, [self(), InUdpSocket, OutUdpSocket, {SrcAddress, SrcPort}]).

spawn_link(InUdpSocket, OutUdpSocket) ->
  spawn_link(InUdpSocket, OutUdpSocket, {any, any}).


loop(Master, InSocket, OutSocket, {SrcAddress, SrcPort}) ->
  ok,
  loop(Master, InSocket, OutSocket, {SrcAddress, SrcPort}).
