-module(eproxy_config).
-author(alex_burkov).

-behaviour(gen_server).

-export([
  get_server_port_number/0,
  get_auth_methods/0,
  get_external_ipv4/0,
  get_external_ipv6/0,
  start_link/0,
  init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3
]).

-include("socks5.hrl").

-define(SERVER, ?MODULE).

-record(state, {
  port_number :: inet:port_number(),
  external_ipv4 = {127, 0, 0, 1} :: inet:ip4_address(),
  external_ipv6 = {0, 0, 0, 0, 0, 0, 0, 1} :: inet:ip6_address(),
  auth_methods = sets:from_list([no_auth]) :: sets:set(auth_method())
}).

-spec get_server_port_number() -> inet:port_number().
get_server_port_number() -> gen_server:call(?SERVER, get_server_port_number).

-spec get_auth_methods() -> sets:set(auth_method()).
get_auth_methods() -> gen_server:call(?SERVER, get_auth_methods).

-spec get_external_ipv4() -> inet:ip4_address().
get_external_ipv4() -> gen_server:call(?SERVER, get_external_ipv4).

-spec get_external_ipv6() -> inet:ip6_address().
get_external_ipv6() -> gen_server:call(?SERVER, get_external_ipv6).

%%%

start_link() -> gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
init([]) ->
  gen_server:cast(self(), init),
  {ok, #state{}}.

handle_call(get_server_port_number, _From, State) -> {reply, State#state.port_number, State};
handle_call(get_auth_methods, _From, State) -> {reply, State#state.auth_methods, State};
handle_call(get_external_ipv4, _From, State) -> {reply, State#state.external_ipv4, State};
handle_call(get_external_ipv6, _From, State) -> {reply, State#state.external_ipv6, State};
handle_call(Request, From, State) -> {stop, {unsupported_call, From, Request}, State}.

handle_cast(init, State) ->
  case application:get_env(server_port) of
    {ok, PortNum} when is_integer(PortNum), PortNum > 0, PortNum =< 16#ffff ->
      {noreply, State#state{port_number = PortNum}};
    Else ->
      {stop, {wrong_port_number, Else}, State}
  end;

handle_cast(Request, State) -> {stop, {unsupported_cast, Request}, State}.
handle_info(Info, State) -> {stop, {unsupported_info, Info}, State}.
terminate(Reason, _State) -> lager:warning("termination, reason:~p", [Reason]).
code_change(_OldVsn, State, _Extra) -> {ok, State}.
