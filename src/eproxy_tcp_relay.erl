-module(eproxy_tcp_relay).
-author(alex_burkov).

-export([spawn_link/2, relay/3]).


spawn_link(InSocket, OutSocket) ->
  erlang:spawn(?MODULE, relay, [self(), InSocket, OutSocket]).


relay(Master, InSocket, OutSocket) ->
  case gen_tcp:recv(InSocket, 0) of
    {ok, Data} ->
      case gen_tcp:send(OutSocket, Data) of
        ok -> ok;
        {error, Reason} ->
          eproxy_client:connection_error(Master, OutSocket, Reason),
          exit(normal)
      end;
    {error, Reason} ->
      eproxy_client:connection_error(Master, InSocket, Reason),
      exit(normal)
  end,
  receive stop -> exit(normal) after 0 -> ok end,
  relay(Master, InSocket, OutSocket).