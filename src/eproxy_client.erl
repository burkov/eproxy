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
  accept/2,
  accept/3,


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
  in_tcp_socket :: gen_tcp:socket(),
  out_tcp_socket :: gen_tcp:socket(),
  in_udp_socket :: gen_udp:socket(),
  out_udp_socket :: gen_udp:socket(),
  relays :: {pid(), pid()}
}).

start_link(Socket) ->
  gen_fsm:start_link(?MODULE, [Socket], []).

init([InSocket]) ->
  {ok, {Address, Port}} = inet:peername(InSocket),
  lager:debug("client connected, ~p:~p", [inet:ntoa(Address), Port]),
  Slave = eproxy_negotiator:spawn_link(InSocket),
  {ok, auth_method_selection, #state{in_tcp_socket = InSocket, negotiator = Slave}, ?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS}.

%%% auth method selection

auth_method_selection({auth_methods, AuthMethods}, #state{in_tcp_socket = Socket, negotiator = Slave} = State) ->
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

request({_, {error, invlaid_address_type}}, #state{in_tcp_socket = Socket} = State) ->
  ?REPLY_AND_STOP(Socket, address_type_not_supported, State);

request({Type, {DestAddress, DestPort}}, #state{in_tcp_socket = InSocket} = State) ->
  case to_ip_address(DestAddress) of
    {error, invalid_address} -> ?REPLY_AND_STOP(InSocket, general_failure, {invalid_address, DestAddress}, State);
    {ok, TargetIpAddress} -> handle_request(Type, {TargetIpAddress, DestPort}, State)
  end;

request({invalid_command, {_Address, _Port}}, #state{in_tcp_socket = Socket} = State) ->
  ?REPLY_AND_STOP(Socket, command_not_supported, State);

request(timeout, State) ->
  lager:warning("request sending took too long (> ~p ms), exiting", [?REQUEST_TIMEOUT_MS]),
  {stop, request_timeout, State};

request(Event, State) -> {stop, {unsupported_event, Event}, State}.
request(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%% accept

accept({accepted, OutSocket, DestAddr, DestPort}, #state{in_tcp_socket = InSocket, negotiator = Slave} = State) ->
  ok = socks5:send_reply(InSocket, succeeded, {DestAddr, DestPort}),
  Slave ! stop,
  OutgoingRelay = eproxy_tcp_relay:spawn_link(InSocket, OutSocket),
  IncomingRelay = eproxy_tcp_relay:spawn_link(OutSocket, InSocket),
  {next_state, relaying, State#state{
    negotiator = undefined,
    out_tcp_socket = OutSocket,
    relays = {OutgoingRelay, IncomingRelay}
  }};
accept({accept_failure, Reason}, #state{in_tcp_socket = InSocket} = State) ->
  ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_accept_incoming_connection, Reason}, State);

accept(Event, State) -> {stop, {unsupported_event, Event}, State}.
accept(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.


%%% relaying

relaying({connection_closed, S}, #state{in_tcp_socket = S} = State) ->
  lager:debug("incoming connection closed"),
  {stop, normal, State};
relaying({connection_error, Reason, S}, #state{in_tcp_socket = S} = State) ->
  lager:debug("incoming connection error"),
  {stop, fixme, State};
relaying({connection_closed, S}, #state{out_tcp_socket = S} = State) ->
  lager:debug("outgoing connection closed"),
  {stop, normal, State};
relaying({connection_error, Reason, S}, #state{out_tcp_socket = S} = State) ->
  lager:debug("outgoing connection error"),
  {stop, fixme, State};
relaying(Event, State) -> {stop, {unsupported_event, Event}, State}.
relaying(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%%

handle_event(Event, _StateName, State) -> {stop, {unsupported_all_state_event, Event}, State}.
handle_sync_event(Event, From, _StateName, State) -> {stop, {unsupported_all_state_sync_event, From, Event}, State}.
handle_info(Info, _StateName, State) -> {stop, {unsupported_info, Info}, State}.
code_change(_OldVsn, StateName, State, _Extra) -> {ok, StateName, State}.
terminate(Reason, StateName, S) ->
  S#state.negotiator ! stop,
  [R ! stop || R <- tuple_to_list(S#state.relays)],
  gen_tcp:close(S#state.in_tcp_socket),
  gen_tcp:close(S#state.out_tcp_socket),
  gen_udp:close(S#state.in_udp_socket),
  gen_udp:close(S#state.out_udp_socket),
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

-spec handle_request(command(), {inet:ip_address(), inet:port_number()}, #state{}) -> {next_state, StateName :: any(), #state{}} | {stop, Reason :: any, #state{}}.
handle_request(connect, {DestAddress, DestPort}, #state{in_tcp_socket = InSocket, negotiator = Slave} = State) ->
  case gen_tcp:connect(DestAddress, DestPort, [binary, {active, false}, {nodelay, true}, {}], ?CONNECT_TIMEOUT_MS) of
    {error, econnrefused} -> ?REPLY_AND_STOP(InSocket, connection_refused, State);
    {error, ehostunreach} -> ?REPLY_AND_STOP(InSocket, host_unreachable, State);
    {error, enetunreach} -> ?REPLY_AND_STOP(InSocket, network_unreachable, State);
    {error, fixme} -> ?REPLY_AND_STOP(InSocket, ttl_expired, State); % FIXME find out appropriate posix error code
    {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
    {ok, OutSocket} ->
      case inet:sockname(OutSocket) of
        {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
        {ok, {BindAddress, BindPort}} ->
          ok = socks5:send_reply(InSocket, succeeded, {BindAddress, BindPort}),
          Slave ! stop,
          OutgoingRelay = eproxy_tcp_relay:spawn_link(InSocket, OutSocket),
          IncomingRelay = eproxy_tcp_relay:spawn_link(OutSocket, InSocket),
          {next_state, relaying, State#state{
            negotiator = undefined,
            out_tcp_socket = OutSocket,
            relays = {OutgoingRelay, IncomingRelay}
          }}
      end
  end;

handle_request(bind, {DestAddress, DestPort}, #state{in_tcp_socket = InSocket, negotiator = Slave} = State) ->
  case gen_tcp:listen(0, [binary, {nodelay, true}, {active, false}]) of
    {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
    {ok, OutSocket} ->
      case inet:sockname(OutSocket) of
        {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
        {ok, {BindAddress, BindPort}} ->
          ok = socks5:send_reply(InSocket, succeeded, {BindAddress, BindPort}),
          Slave ! {accept_connection_from, OutSocket, DestAddress, DestPort},
          {next_state, accept, State}
      end
  end;

handle_request(udp_associate, {DestAddress, DestPort}, #state{in_tcp_socket = ControlSocket, negotiator = Slave} = State) ->
  case gen_udp:open(0, [binary, {active, false}]) of
    {error, Reason} -> ?REPLY_AND_STOP(ControlSocket, general_failure, {failed_to_open_udp_relay, Reason}, State);
    {ok, InUdpSocket} ->
      case inet:sockname(InUdpSocket) of
        {error, Reason} -> ?REPLY_AND_STOP(ControlSocket, general_failure, {failed_to_open_udp_relay, Reason}, State);
        {ok, {InRelayAddress, InRelayPort}} ->
          case gen_udp:open(0, [binary, {active, false}]) of
            {error, Reason} ->
              gen_udp:close(InUdpSocket),
              ?REPLY_AND_STOP(ControlSocket, general_failure, {failed_to_open_udp_relay, Reason}, State);
            {ok, OutUdpSocket} ->
              ok = socks5:send_reply(succeeded, {InRelayAddress, InRelayPort}),
              Slave ! stop,
              OutgoingRelay = eproxy_udp_relay:spawn_link(InUdpSocket, OutUdpSocket, {DestAddress, DestPort}),
              IncomingRelay = eproxy_udp_relay:spawn_link(OutUdpSocket, InUdpSocket),
              {next_state, relaying, State#state{
                in_udp_socket = InUdpSocket,
                out_udp_socket = OutUdpSocket,
                relays = {OutgoingRelay, IncomingRelay}
              }}
          end
      end
  end.
