-module(eproxy_client).
-author(alex_burkov).

-behaviour(gen_fsm).

-export([
  start_link/1,
  init/1,

  auth_method_selection/2,
  auth_method_selection/3,
  authentication/2,
  authentication/3,
  request/2,
  request/3,
  state_name/2,
  state_name/3,
  handle_event/3,
  handle_sync_event/4,
  handle_info/3,
  terminate/3,
  code_change/4,
  slave/2
]).

-include("socks5.hrl").

-define(RECV_TIMEOUT_MS, 1000).
-define(AUTH_METHOD_NEGOTIATION_TIMEOUT_MS, 2000).
-define(AUTHENTICATION_TIMEOUT_MS, 2000).
-define(REQUEST_TIMEOUT_MS, 2000).

-record(state, {
  negotiation_helper :: pid(),
  in_socket :: gen_tcp:socket()
}).

start_link(Socket) ->
  gen_fsm:start_link(?MODULE, [Socket], []).

init([Socket]) ->
  {ok, {Address, Port}} = inet:peername(Socket),
  lager:debug("client connected, ~p:~p", [inet:ntoa(Address), Port]),
  Slave = eproxy_negotiation:start_link(Socket),
  {ok, auth_method_selection, #state{in_socket = Socket, negotiation_helper = Slave}, ?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS}.

%%% auth method selection

auth_method_selection({auth_methods, AuthMethods}, #state{in_socket = Socket, negotiation_helper = Slave} = State) ->
  ClientMethodsSet = sets:from_list([AuthMethods]),
  ServerMethodsSet = eproxy_config:get_auth_methods(),

  case sets:is_element(no_auth, sets:intersection(ClientMethodsSet, ServerMethodsSet)) of
    false ->
      ok = socks5:send_auth_method_selection_reject(Socket),
      {stop, auth_method_not_supported};
    true ->
      ok = socks5:send_auth_method_selection_reply(Socket, no_auth),
      Slave ! {do_authentication, no_auth},
      {next_state, authentication, ?AUTHENTICATION_TIMEOUT_MS}
  end;

auth_method_selection(timeout, State) ->
  lager:warning("auth method negotiation took too long (> ~p ms), exiting", [?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS]),
  {stop, auth_method_selection_timeout, State}.

auth_method_selection(Event, _From, State) ->
  lager:warning("unexpected sync event ~p", [Event]),
  {stop, unsupported_sync_event, State}.


%%% authentication

authentication(authenticated, #state{negotiation_helper = Slave} = State) ->
  Slave ! recv_request,
  {next_state, request, State, ?REQUEST_TIMEOUT_MS};

authentication({authentication_failure, Reason}, #state{negotiation_helper = Slave} = State) ->
  lager:warning("authentication failed, reason: ~p", [Reason]),
  {stop, authentication_failure, State};

authentication(timeout, State) ->
  lager:warning("authentication subroutine took too long (> ~p ms), exiting", [?AUTHENTICATION_TIMEOUT_MS]),
  {stop, authentication_timeout, State}.

authentication(Event, _From, State) ->
  lager:warning("unexpected sync event ~p", [Event]),
  {stop, unsupported_sync_event, State}.

%%% request

request({connect, {Address, Port}}, State) ->
  {next_state, request, State};

request({bind, {Address, Port}}, State) ->
  {next_state, request, State};

request({udp_associate, {Address, Port}}, State) ->
  {next_state, request, State};

request(timeout, State) ->
  lager:warning("request sending took too long (> ~p ms), exiting", [?REQUEST_TIMEOUT_MS]),
  {stop, request_timeout, State}.

request(Event, _From, State) ->
  lager:warning("unexpected sync event ~p", [Event]),
  {stop, unsupported_sync_event, State}.

%%%

handle_event(Event, _StateName, State) ->
  lager:warning("unexpected all state event ~p", [Event]),
  {stop, unsupported_all_state_event, State}.

handle_sync_event(Event, _From, _StateName, State) ->
  lager:warning("unexpected all state sync event ~p", [Event]),
  {stop, unsupported_all_state_sync_event, State}.

handle_info(Info, _StateName, State) ->
  lager:warning("unexpected info ~p", [Info]),
  {stop, unsupported_info, State}.

terminate(Reason, StateName, #state{in_socket = Socket}) ->
  gen_tcp:close(Socket),
  lager:warning("termination in state '~p', reason: ~p", [StateName, Reason]).

code_change(_OldVsn, StateName, State, _Extra) -> {ok, StateName, State}.