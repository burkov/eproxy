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
  relaying/2,
  relaying/3,


  handle_event/3,
  handle_sync_event/4,
  handle_info/3,
  terminate/3,
  code_change/4
]).

-include("socks5.hrl").
-include_lib("kernel/include/inet.hrl").

-define(RECV_TIMEOUT_MS, 1000).
-define(AUTH_METHOD_NEGOTIATION_TIMEOUT_MS, 2000).
-define(AUTHENTICATION_TIMEOUT_MS, 2000).
-define(REQUEST_TIMEOUT_MS, 2000).
-define(CONNECT_TIMEOUT_MS, 2000).

-record(state, {
  negotiator :: pid(),
  relays :: {pid(), pid()},
  in_socket :: gen_tcp:socket(),
  out_socket :: gen_tcp:socket()
}).

start_link(Socket) ->
  gen_fsm:start_link(?MODULE, [Socket], []).

init([Socket]) ->
  {ok, {Address, Port}} = inet:peername(Socket),
  lager:debug("client connected, ~p:~p", [inet:ntoa(Address), Port]),
  Slave = eproxy_negotiation:start_link(Socket),
  {ok, auth_method_selection, #state{in_socket = Socket, negotiator = Slave}, ?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS}.

%%% auth method selection

auth_method_selection({auth_methods, AuthMethods}, #state{in_socket = Socket, negotiator = Slave} = State) ->
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
  {stop, auth_method_selection_timeout, State};

auth_method_selection(Event, State) -> {stop, {unsupported_event, Event}, State}.
auth_method_selection(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%% authentication

authentication(authenticated, #state{negotiator = Slave} = State) ->
  Slave ! recv_request,
  {next_state, request, State, ?REQUEST_TIMEOUT_MS};

authentication({authentication_failure, Reason}, State) -> {stop, {authentication_failure, Reason}, State};

authentication(timeout, State) ->
  lager:warning("authentication subroutine took too long (> ~p ms), exiting", [?AUTHENTICATION_TIMEOUT_MS]),
  {stop, authentication_timeout, State};

authentication(Event, State) -> {stop, {unsupported_event, Event}, State}.
authentication(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%% request

-define(REPLY_AND_STOP(Socket, Reply, Reason, State), begin socks5:send_reply(Socket, Reply), {stop, Reason, State} end).
-define(REPLY_AND_STOP(Socket, Reason, State), ?REPLY_AND_STOP(Socket, Reason, Reason, State)).

request({_, {error, invlaid_address_type}}, #state{in_socket = Socket} = State) ->
  ?REPLY_AND_STOP(Socket, address_type_not_supported, State);

request({connect, {DestAddress, DestPort}}, #state{in_socket = InSocket, negotiator = Slave} = State) ->
  case to_ip_address(DestAddress) of
    {error, invalid_address} -> ?REPLY_AND_STOP(InSocket, general_failure, {invalid_address, DestAddress}, State);
    {ok, TargetIpAddress} ->
      case gen_tcp:connect(TargetIpAddress, DestPort, [binary, {active, false}, {nodelay, true}, {}], ?CONNECT_TIMEOUT_MS) of
        {error, econnrefused} -> ?REPLY_AND_STOP(InSocket, connection_refused, State);
        {error, ehostunreach} -> ?REPLY_AND_STOP(InSocket, host_unreachable, State);
        {error, enetunreach} -> ?REPLY_AND_STOP(InSocket, network_unreachable, State);
        {error, fixme} -> ?REPLY_AND_STOP(InSocket, ttl_expired, State); % FIXME find out appropriate posix error code
        {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
        {ok, OutSocket} ->
          case inet:sockname(OutSocket) of
            {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
            {ok, {BindAddress, BindPort}} ->
              socks5:send_reply(InSocket, succeeded, {BindAddress, BindPort}),
              Slave ! stop,
              OutgoingRelay = eproxy_relay:spawn_link(self(), InSocket, OutSocket),
              IncomingRelay = eproxy_relay:spawn_link(self(), OutSocket, InSocket),
              {next_state, relaying, State#state{
                negotiator = undefined,
                relays = {OutgoingRelay, IncomingRelay},
                out_socket = OutSocket
              }}
          end
      end
  end;

request({bind, {Address, Port}}, State) ->
  {next_state, request, State};

request({udp_associate, {Address, Port}}, State) ->
  {next_state, request, State};

request({invalid_command, {Address, Port}}, #state{in_socket = Socket} = State) ->
  socks5:send_reply(Socket, command_not_supported),
  {stop, command_not_supported, State};

request(timeout, State) ->
  lager:warning("request sending took too long (> ~p ms), exiting", [?REQUEST_TIMEOUT_MS]),
  {stop, request_timeout, State};

request(Event, State) -> {stop, {unsupported_event, Event}, State}.
request(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%% relaying

relaying({connection_closed, S}, #state{in_socket = S} = State) ->
  lager:debug("incoming connection closed"),
  {stop, normal, State};
relaying({connection_error, Reason, S}, #state{in_socket = S} = State) ->
  lager:debug("incoming connection error"),
  {stop, fixme, State};
relaying({connection_closed, S}, #state{out_socket = S} = State) ->
  lager:debug("outgoing connection closed"),
  {stop, normal, State};
relaying({connection_error, Reason, S}, #state{out_socket = S} = State) ->
  lager:debug("outgoing connection error"),
  {stop, fixme, State};
relaying(Event, State) -> {stop, {unsupported_event, Event}, State}.
relaying(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%%

handle_event(Event, _StateName, State) -> {stop, {unsupported_all_state_event, Event}, State}.
handle_sync_event(Event, From, _StateName, State) -> {stop, {unsupported_all_state_sync_event, From, Event}, State}.
handle_info(Info, _StateName, State) -> {stop, {unsupported_info, Info}, State}.
code_change(_OldVsn, StateName, State, _Extra) -> {ok, StateName, State}.
terminate(Reason, StateName, #state{negotiator = N, in_socket = InSocket, out_socket = OutSocket, relays = Relays}) ->
  N ! stop,
  [R ! stop || R <- tuple_to_list(Relays)],
  gen_tcp:close(InSocket),
  gen_tcp:close(OutSocket),
  lager:warning("termination in state '~p', reason: ~p", [StateName, Reason]).


-spec to_ip_address(inet:ip_address() | string()) -> {ok, inet:ip_address()} | {error, invalid_address}.
to_ip_address(DestAddress) ->
  case is_tuple(DestAddress) of
    true ->
      case inet:ntoa(DestAddress) of
        {error, einval} -> {error, invalid_address};
        _ -> {ok, DestAddress}
      end;
    false ->
      case inet:gethostbyname(DestAddress) of
        {ok, #hostent{h_addr_list = []}} -> {error, invalid_address};
        {ok, #hostent{h_addr_list = List}} -> {ok, lists:nth(random:uniform(length(List)), List)};
        {error, _} -> {error, invalid_address}
      end
  end.
