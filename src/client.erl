-module(client).
-author(alex_burkov).

-behaviour(gen_server).

-export([
  start_link/1,
  init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3
]).

-record(state, {}).

start_link(Socket) ->
  gen_server:start_link(?MODULE, [Socket], []).

init([Port]) ->
  lager:debug("client started, port: ~p", [Port]),
  {ok, #state{}}.

handle_call(Request, _From, State) ->
  lager:warning("unexpected call ~p", [Request]),
  {reply, ok, State}.

handle_cast(Request, State) ->
  lager:warning("unexpected cast ~p", [Request]),
  {noreply, State}.

handle_info(Info, State) ->
  lager:warning("unexpected info ~p", [Info]),
  {noreply, State}.

terminate(Reason, _State) ->
  lager:warning("termination, reason:~p", [Reason]).

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
