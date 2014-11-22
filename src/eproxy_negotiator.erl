-module(eproxy_negotiator).
-author(alex_burkov).

-export([spawn_link/1, loop/2]).

-define(NEXT_COMMAND_TIMEOUT_MS, 3000).


spawn_link(Socket) when is_port(Socket)->
  (Pid = erlang:spawn_link(?MODULE, loop, [Socket, self()])) ! recv_auth_method_selection_request,
  Pid.

loop(Socket, Master) ->
  receive
    recv_auth_method_selection_request ->
      {ok, Methods} = socks5:recv_auth_method_selection_request(Socket),
      eproxy_client:auth_methods(Master, Methods);
    {do_authentication, no_auth} -> eproxy_client:authentication_succeeded(Master);
    {do_authentication, _Method} -> eproxy_client:authentication_failure(Master, auth_type_not_supported);
    recv_request ->
      {ok, Request} = socks5:recv_request(Socket),
      eproxy_client:client_request(Master, Request);
    {accept_connection_from, FromSocket, {DestAddress, DestPort}} ->
      case gen_tcp:accept(FromSocket) of
        {ok, OutSocket} ->
          case inet:peername(OutSocket) of
            {ok, {DestAddress, DestPort}} ->
              ok = gen_tcp:controlling_process(OutSocket, Master),
              eproxy_client:connection_accepted(Master, OutSocket, {DestAddress, DestPort});
            {ok, {OtherAddress, OtherPort}} ->
              lager:warning("incoming connection from: ~p:~p, expected ~p:~p", [OtherAddress, OtherPort, DestAddress, DestPort]),
              gen_tcp:close(OutSocket),
              self() ! {accept_connection_from, FromSocket, {DestAddress, DestPort}}
          end;
        {error, Reason} ->
          eproxy_client:accept_failure(Master, Reason)
      end;
    stop -> exit(normal)
  after ?NEXT_COMMAND_TIMEOUT_MS -> exit(hung_detected)
  end,
  loop(Socket, Master).