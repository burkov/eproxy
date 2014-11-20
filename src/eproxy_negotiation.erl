-module(eproxy_negotiation).
-author(alex_burkov).

-export([start_link/1, loop/2]).


start_link(Socket) when is_port(Socket)->
  (Pid = erlang:spawn_link(?MODULE, loop, [Socket, self()])) ! recv_auth_method_selection_request,
  Pid.

loop(Socket, Master) ->
  receive
    recv_auth_method_selection_request ->
      {ok, Methods} = socks5:recv_auth_method_selection_request(Socket),
      gen_fsm:send(Master, {auth_methods, Methods});
    {do_authentication, no_auth} ->
      gen_fsm:send(Master, authenticated);
    {do_authentication, _Method} ->
      gen_fsm:send(Master, {authentication_failure, auth_type_not_supported});
    recv_request ->
      {ok, Request} = socks5:recv_request(Socket),
      gen_fsm:send(Master, Request);
    stop ->
      exit(normal)
  end,
  loop(Socket, Master).
