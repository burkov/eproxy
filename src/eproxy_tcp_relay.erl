-module(eproxy_tcp_relay).
-author(alex_burkov).

-export([spawn_link/2, relay/3]).


spawn_link({InSocket, OutSocket}, {InName, OutName}) ->
  Pid = erlang:spawn(?MODULE, relay, [self(), {InSocket, OutSocket}, {InName, OutName}]),
  ok = gen_tcp:controlling_process(InSocket, Pid),
  Pid.

relay(Master, {InSocket, OutSocket}, {InName, OutName}) ->
  case gen_tcp:recv(InSocket, 0) of
    {ok, Data} ->
      case gen_tcp:send(OutSocket, Data) of
        ok -> ok;
        {error, Reason} ->
          eproxy_client:connection_error(Master, OutName, Reason),
          gen_tcp:close(InSocket),
          exit(normal)
      end;
    {error, Reason} ->
      eproxy_client:connection_error(Master, InName, Reason),
      gen_tcp:close(InSocket),
      exit(normal)
  end,
  receive stop -> exit(normal) after 0 -> ok end,
  relay(Master, {InSocket, OutSocket}, {InName, OutName}).