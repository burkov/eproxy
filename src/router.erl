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

-record(state, {
  socket :: gen_tcp:socket()
}).

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
  PortNum = config:get_server_port_number(),
  {ok, Socket} = gen_tcp:listen(PortNum, [binary, {nodelay, true}, {active, false}, {reuseaddr, true}]),
  self() ! accept,
  {ok, #state{socket = Socket}}.

handle_call(Request, _From, State) ->
  lager:warning("unexpected call ~p", [Request]),
  {reply, ok, State}.

handle_cast(Request, State) ->
  lager:warning("unexpected cast ~p", [Request]),
  {noreply, State}.

handle_info(accept, #state{socket = Socket} = State) ->
  case gen_tcp:accept(Socket) of
    {ok, ClientSocket} ->
      client_sup:start_client(ClientSocket);
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
