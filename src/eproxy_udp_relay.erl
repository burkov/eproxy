-module(eproxy_udp_relay).
-author(alex_burkov).

-export([spawn_link/4, mangled_to_unmangled/4, unmangled_to_mangled/4]).


spawn_link(in, InUdpSocket, OutUdpSocket, {SrcAddress, SrcPort}) ->
  erlang:spawn_link(?MODULE, mangled_to_unmangled, [self(), InUdpSocket, OutUdpSocket, {SrcAddress, SrcPort}]);

spawn_link(out, InUdpSocket, OutUdpSocket, {DestAddress, DestPort}) ->
  erlang:spawn_link(?MODULE, unmangled_to_mangled, [self(), InUdpSocket, OutUdpSocket, {DestAddress, DestPort}]).


mangled_to_unmangled(Master, InSocket, OutSocket, {FromAddress, FromPort} = AP) ->
  case socks5:recv_udp_datagram(InSocket) of
    {ok, {FromAddress, FromPort}, {ToAddress, ToPort}, 0, Packet} ->
      case gen_udp:send(OutSocket, ToAddress, ToPort, Packet) of
        ok -> ok;
        {error, Reason} ->
          eproxy_client:connection_error(Master, eproxy:peername_as_string(InSocket), Reason),
          exit(normal)
      end;
    {ok, {OtherAddress, OtherPort}, {ToAddress, ToPort}, 0, _} ->
      lager:warning("got UDP packet from unknown ip:port ~p:~p (expected ~p:~p), dropping", [OtherAddress, OtherPort, ToAddress, ToPort]);
    {ok, _, _, N, _} when N =/= 0 ->
      lager:warning("re-fragmentation isn't supported, dropping packet");
    {error, Reason} ->
      eproxy_client:connection_error(Master, eproxy:ap_as_string(AP), Reason),
      exit(normal)
  end,
  mangled_to_unmangled(Master, InSocket, OutSocket, {FromAddress, FromPort}).

unmangled_to_mangled(Master, InSocket, OutSocket, {DestAddress, DestPort} = AP) ->
  case gen_udp:recv(InSocket, 0) of
    {ok, {Address, Port, Packet}} ->
      case gen_udp:send(OutSocket, DestAddress, DestPort, socks5:udp_datagram(0, {Address, Port}, Packet)) of
        ok -> ok;
        {error, Reason} ->
          eproxy_client:connection_error(Master, eproxy:peername_as_string(InSocket), Reason),
          exit(normal)
      end;
    {error, Reason} ->
      eproxy_client:connection_error(Master, eproxy:ap_as_string(AP), Reason),
      exit(normal)
  end,
  unmangled_to_mangled(Master, InSocket, OutSocket, {DestAddress, DestPort}).