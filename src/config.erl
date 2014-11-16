-module(config).
-author(alex_burkov).

-behaviour(gen_server).

-export([
  get_server_port_number/0,
  get_auth_methods/0,
  start_link/0,
  init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3
]).

-include("eproxy.hrl").

-define(SERVER, ?MODULE).

-record(state, {
  port_number :: inet:port_number(),
  auth_methods = [no_auth] :: [auth_method()]
}).

-spec get_server_port_number() -> inet:port_number().
get_server_port_number() ->
  gen_server:call(?SERVER, get_server_port_number).

-spec get_auth_methods() -> sets:set(auth_method()).
get_auth_methods() ->
  gen_server:call(?SERVER, get_auth_methods).

%%%

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
  gen_server:cast(self(), init),
  {ok, #state{}}.

handle_call(get_server_port_number, _From, State) ->
  {reply, State#state.port_number, State};

handle_call(get_auth_methods, _From, State) ->
  {reply, sets:from_list([no_auth]), State};

handle_call(Request, _From, State) ->
  lager:warning("unexpected call ~p", [Request]),
  {reply, ok, State}.

handle_cast(init, State) ->
  case application:get_env(server_port) of
    {ok, PortNum} when is_integer(PortNum), PortNum > 0, PortNum =< 16#ffff ->
      {noreply, State#state{port_number = PortNum}};
    Else ->
      lager:error("server_port number is incorrect: ~p", [Else]),
      {stop, bad_config, State}
  end;

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
