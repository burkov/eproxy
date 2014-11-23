-module(eproxy_acceptor).
-author(alex_burkov).

-behaviour(gen_server).

%%% This actor listens to 1080 port, accepts incoming connection which are to be proxified
%%% and deligates their serving to client actor(s)

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
  put(owners, []), % FIXME for debug only. see fun print_port_owners_on_change/0
  PortNum = eproxy_config:get_server_port_number(),
  {ok, Socket} = gen_tcp:listen(PortNum, [
    binary,
    {nodelay, true},
    {active, false},
    {reuseaddr, true},
    {backlog, 1024}
  ]),
  self() ! accept,
  {ok, #state{socket = Socket}}.

handle_info(accept, #state{socket = Socket} = State) ->
  case gen_tcp:accept(Socket, ?ACCEPT_TIMEOUT_MS) of
    {ok, ClientSocket} ->
      try
        {ok, Pid} = eproxy_client_sup:serve_client(ClientSocket),
        gen_tcp:controlling_process(ClientSocket, Pid) % erlang will close it if process crashes
      catch Type:Reason ->
        lager:warning("failed to spawn worker for ~p, got ~p with reason: ~p", [inet:peername(ClientSocket), Type, Reason]),
        gen_tcp:close(ClientSocket)
      end;
    {error, timeout} ->
      %% timeout was introduced to let this actor receive 'shutdown' from supervisor
      %% we can also use this to grab some stats, like opened ports to not let them leak
      print_port_owners_on_change();
    {error, Reason} ->
      lager:warning("failed to accept incoming TCP connection, reason: ~p", [Reason])
  end,
  self() ! accept,
  {noreply, State};

handle_info(Info, State) -> {stop, {unsupported_info, Info}, State}.
handle_call(Request, From, State) -> {stop, {unsupported_call, From, Request}, State}.
handle_cast(Request, State) -> {stop, {unsupported_cast, Request}, State}.
terminate(Reason, _State) -> lager:warning("termination, reason:~p", [Reason]).
code_change(_OldVsn, State, _Extra) -> {ok, State}.

-spec opened_inet_ports_owners() -> [pid()].
%% @doc returns list of all node's TCP socket owners
opened_inet_ports_owners() ->
  PortInfos = [erlang:port_info(P) || P <- erlang:ports()],
  TcpPortInfos = [P || P <- PortInfos,
    (proplists:get_value(name, P) =:= "tcp_inet" orelse proplists:get_value(name, P) =:= "udp_inet")],
  lists:flatten([proplists:get_value(links, P) || P <- TcpPortInfos]).

-spec print_port_owners_on_change() -> ok.
%% @doc will print only changes to last known list of opened TCP sockets owners
print_port_owners_on_change() ->
  %% process dictionary used here only for debug purposes
  OldOwners = get(owners),
  Owners = opened_inet_ports_owners(),
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
%% @doc pretty-printer for non-zero integers' delta. adds '+' sign in front of positive deltas.
pp_delta(0) -> exit(bad_arg);
pp_delta(X) when X < 0 -> io_lib:format("~w", [X]);
pp_delta(X) when X > 0 -> io_lib:format("+~w", [X]).