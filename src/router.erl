-module(router).
-author(alex_burkov).

-behaviour(gen_server).

-export([
  start_link/0,
  init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3
]).

-define(SERVER, ?MODULE).
-define(ACCEPT_TIMEOUT_MS, 1000).

-record(state, {
  socket :: gen_tcp:socket()
}).

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
  put(owners, []), % FIXME remove, this is for debug only
  PortNum = config:get_server_port_number(),
  {ok, Socket} = gen_tcp:listen(PortNum, [
    binary,
    {nodelay, true},
    {active, false},
    {reuseaddr, true},
    {backlog, 1024}
  ]),
  self() ! accept,
  {ok, #state{socket = Socket}}.

handle_call(Request, _From, State) ->
  lager:warning("unexpected call ~p", [Request]),
  {reply, ok, State}.

handle_cast(Request, State) ->
  lager:warning("unexpected cast ~p", [Request]),
  {noreply, State}.

handle_info(accept, #state{socket = Socket} = State) ->
  case gen_tcp:accept(Socket, ?ACCEPT_TIMEOUT_MS) of
    {ok, ClientSocket} ->
      try
        {ok, Pid} = client_sup:start_client(ClientSocket),
        gen_tcp:controlling_process(ClientSocket, Pid) % erlang will close it if process crashes
      catch Type:Reason ->
        lager:warning("failed to spawn worker for ~p, got ~p reason: ~p", [ClientSocket, Type, Reason]),
        gen_tcp:close(ClientSocket)
      end;
    {error, timeout} ->
      %% to let this actor receive 'shutdown' from supervisor
      %% FIXME remove this debug, it is too noisy
      print_owners_on_change();
    {error, Reason} ->
      lager:warning("failed to accept incoming TCP connection, reason: ~p", [Reason])
  end,
  self() ! accept,
  {noreply, State};

handle_info(Info, State) ->
  lager:warning("unexpected info ~p", [Info]),
  {noreply, State}.

terminate(Reason, _State) ->
  lager:warning("termination, reason:~p", [Reason]).

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

opened_tcp_ports_owners() ->
  PortInfos = [erlang:port_info(P) || P <- erlang:ports()],
  TcpPortInfos = [P || P <- PortInfos, proplists:get_value(name, P) =:= "tcp_inet"],
  lists:flatten([proplists:get_value(links, P) || P <- TcpPortInfos]).

print_owners_on_change() ->
  OldOwners = get(owners),
  Owners = opened_tcp_ports_owners(),
  Count = length(Owners),
  Delta = Count - length(OldOwners),
  put(owners, Owners),
  case OldOwners =/= Owners of
    true ->
      lager:debug("port owners ~s! (total ~p), list: ~p", [pp_delta(Delta), Count, Owners]);
    false ->
      ok
  end.

-spec pp_delta(integer()) -> string().
%% @doc pretty-printer for non-zero integers' delta
pp_delta(0) -> exit(bad_arg);
pp_delta(X) when X < 0 ->
  io_lib:format("~w", [X]);
pp_delta(X) when X > 0 ->
  io_lib:format("+~w", [X]).