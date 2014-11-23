-module(eproxy_client).
-author(alex_burkov).

-behaviour(gen_fsm).

-export([

  auth_methods/2,
  authentication_succeeded/1,
  authentication_failure/2,
  client_request/2,
  connection_accepted/3,
  accept_failure/2,
  connection_error/3,

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

-define(VAR(Var), lager:debug("Variable ~p = ~p", [??Var, Var])).

-define(RECV_TIMEOUT_MS, 1000).
-define(AUTH_METHOD_NEGOTIATION_TIMEOUT_MS, 2000).
-define(AUTHENTICATION_TIMEOUT_MS, 2000).
-define(REQUEST_TIMEOUT_MS, 2000).
-define(CONNECT_TIMEOUT_MS, 2000).
-define(ACCEPT_TIMEOUT_MS, 2000).

-record(state, {
  negotiator :: pid(),
  controlling_socket :: gen_tcp:socket(),
  client_name :: string(),
  endpoint_name :: string()
}).

%%% API

-spec auth_methods(pid(), [auth_method()]) -> ok.
%% @doc client offers auth methods
auth_methods(Pid, Methods) -> gen_fsm:send_event(Pid, {auth_methods, Methods}).

-spec authentication_failure(pid(), any()) -> ok.
%% @doc auth procedure failed
authentication_failure(Pid, Reason) -> gen_fsm:send_event(Pid, {authentication_failure, Reason}).

-spec authentication_succeeded(pid()) -> ok.
%% @doc client and authentication agent succesfully fullfilled auth procedure
authentication_succeeded(Pid) -> gen_fsm:send_event(Pid, authenticated).

-spec client_request(pid(), {command(), address_and_port()}) -> ok.
%% @doc client sends request (CONNECT, BIND, UDP ASSOCIATE)
client_request(Pid, Request) -> gen_fsm:send_event(Pid, Request).

-spec connection_accepted(pid(), gen_tcp:socket(), address_and_port()) -> ok.
%% @doc used only in BIND, address given by BIND request just've connected
connection_accepted(Pid, Socket, AddressPort) -> gen_fsm:send_event(Pid, {accepted, Socket, AddressPort}).

-spec accept_failure(pid(), any()) -> ok.
%% @doc used only in BIND, address given by BIND failed to connect relay socket
accept_failure(Pid, Reason) -> gen_fsm:send_event(Pid, {accept_failure, Reason}).

-spec connection_error(pid(), string(), any()) -> ok.
%% @doc relay agent reports failure
connection_error(Pid, CloserName, closed) -> gen_fsm:send_event(Pid, {connection_closed, CloserName});
connection_error(Pid, GuiltyName, Reason) -> gen_fsm:send_event(Pid, {connection_error, GuiltyName, Reason}).


%%%

start_link(Socket) -> gen_fsm:start_link(?MODULE, [Socket], []).

init([InSocket]) ->
  ClientName = eproxy:peername_as_string(InSocket),
  lager:info("~s connects", [ClientName]),
  Slave = eproxy_negotiator:spawn_link(InSocket),
  {ok, auth_method_selection, #state{
    controlling_socket = InSocket,
    negotiator = Slave,
    client_name = ClientName
  }, ?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS}.

%%% auth method selection

auth_method_selection({auth_methods, AuthMethods}, #state{controlling_socket = InSocket, negotiator = Slave} = State) ->
  ClientMethodsSet = sets:from_list(AuthMethods),
  ServerMethodsSet = eproxy_config:get_auth_methods(),
  case sets:is_element(no_auth, sets:intersection(ClientMethodsSet, ServerMethodsSet)) of
    false ->
      ok = socks5:send_auth_method_selection_reject(InSocket),
      {stop, auth_method_not_supported, State};
    true ->
      ok = socks5:send_auth_method_selection_reply(InSocket, no_auth),
      Slave ! {do_authentication, no_auth},
      {next_state, authentication, State, ?AUTHENTICATION_TIMEOUT_MS}
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

pp_type(connect) -> "CONNECT to";
pp_type(bind) -> "BIND from";
pp_type(udp_associate) -> "UDP ASSOCIATE with".

request({_, {error, invlaid_address_type}}, #state{controlling_socket = Socket} = State) ->
  ?REPLY_AND_STOP(Socket, address_type_not_supported, State);

request({Type, {DestAddress, DestPort}}, #state{controlling_socket = Socket, client_name = ClientName} = State) ->
  EndpointName = eproxy:ap_as_string({DestAddress, DestPort}),
  lager:info("~s requests ~s ~s", [ClientName, pp_type(Type), EndpointName]),
  case to_ip_address(DestAddress) of
    {error, invalid_address} -> ?REPLY_AND_STOP(Socket, general_failure, {invalid_address, DestAddress}, State);
    {ok, TargetIpAddress} -> handle_request(Type, {TargetIpAddress, DestPort}, State#state{endpoint_name = EndpointName})
  end;

request({invalid_command, {_Address, _Port}}, #state{controlling_socket = Socket} = State) ->
  ?REPLY_AND_STOP(Socket, command_not_supported, State);

request(timeout, State) ->
  lager:warning("request sending took too long (> ~p ms), exiting", [?REQUEST_TIMEOUT_MS]),
  {stop, request_timeout, State};

request(Event, State) -> {stop, {unsupported_event, Event}, State}.
request(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%% accept

accept({accepted, OutSocket, {DestAddress, DestPort} = AP}, #state{
  controlling_socket = ControllingSocket,
  negotiator = Slave,
  client_name = ClientName,
  endpoint_name = EndpointName
} = State) ->
  OutClientName = eproxy:ap_as_string(AP),
  lager:info("~s BINDed to ~s", [ClientName, EndpointName]),
  ok = socks5:send_reply(ControllingSocket, succeeded, {DestAddress, DestPort}),
  Slave ! stop,
  eproxy_tcp_relay:spawn_link({ControllingSocket, OutSocket}, {ClientName, OutClientName}),
  eproxy_tcp_relay:spawn_link({OutSocket, ControllingSocket}, {OutClientName, ClientName}),
  {next_state, relaying, State#state{
    negotiator = undefined,
    controlling_socket = undefined
  }};
accept({accept_failure, Reason}, #state{controlling_socket = InSocket} = State) ->
  ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_accept_incoming_connection, Reason}, State);

accept(timeout, State) ->
  lager:warning("accepting of incoming connect took too long (> ~p ms), exiting", [?ACCEPT_TIMEOUT_MS]),
  {stop, accept_timeout, State};

accept(Event, State) -> {stop, {unsupported_event, Event}, State}.
accept(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.


%%% relaying

relaying({connection_closed, Guilty}, #state{client_name = ClientName, endpoint_name = EndpointName} = S) ->
  lager:info("~s->~s: connection closed by ~s", [ClientName, EndpointName, Guilty]),
  {stop, normal, S};

relaying({connection_error, Guilty, Reason}, #state{client_name = ClientName, endpoint_name = EndpointName} = S) ->
  lager:info("~s->~s, network i/o failed by ~s, reason: ~p", [ClientName, EndpointName, Guilty, Reason]),
  {stop, outgoing_connection_error, S};

relaying(Event, State) -> {stop, {unsupported_event, Event}, State}.
relaying(Event, From, State) -> {stop, {unsupported_sync_event, From, Event}, State}.

%%%
handle_info({tcp_closed, Socket}, _StateName, #state{controlling_socket = Socket, client_name = ClientName} = State) ->
  lager:info("~s controlling TCP socket closed, UDP relay destroyed", [ClientName]),
  {stop, normal, State};
handle_info(Info, _StateName, State) -> {stop, {unsupported_info, Info}, State}.
handle_event(Event, _StateName, State) -> {stop, {unsupported_all_state_event, Event}, State}.
handle_sync_event(Event, From, _StateName, State) -> {stop, {unsupported_all_state_sync_event, From, Event}, State}.
code_change(_OldVsn, StateName, State, _Extra) -> {ok, StateName, State}.
terminate(Reason, StateName, #state{negotiator = Slave, controlling_socket = Socket}) ->
  case Slave of undefined -> ok; _ -> Slave ! stop end,
  case Socket of undefined -> ok; _ -> gen_tcp:close(Socket) end,
  log_on_abnormal(StateName, Reason).

log_on_abnormal(_, normal) -> ok;
log_on_abnormal(StateName, Reason) ->
  lager:warning("termination in state '~p', reason: ~p", [StateName, Reason]).


-spec to_ip_address(inet:ip_address() | string()) -> {ok, inet:ip_address()} | {error, invalid_address}.
%% @doc converts given addres (ip address or domain name) into ip address
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
handle_request(connect, {DestAddress, DestPort}, #state{
  controlling_socket = InSocket,
  client_name = ClientName,
  negotiator = Slave,
  endpoint_name = EndpointName
} = State) ->
  case gen_tcp:connect(DestAddress, DestPort, [binary, {active, false}, {nodelay, true}], ?CONNECT_TIMEOUT_MS) of
    {error, econnrefused} -> ?REPLY_AND_STOP(InSocket, connection_refused, State);
    {error, ehostunreach} -> ?REPLY_AND_STOP(InSocket, host_unreachable, State);
    {error, enetunreach} -> ?REPLY_AND_STOP(InSocket, network_unreachable, State);
    {error, fixme} -> ?REPLY_AND_STOP(InSocket, ttl_expired, State); % FIXME find out appropriate posix error code
    {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
    {ok, OutSocket} ->
      case inet:sockname(OutSocket) of
        {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
        {ok, {BindAddress, BindPort} = AP} ->
          lager:info("~s->~s CONNECTed via ~s", [ClientName, EndpointName, eproxy:ap_as_string(AP)]),
          ok = socks5:send_reply(InSocket, succeeded, {BindAddress, BindPort}),
          Slave ! stop,
          eproxy_tcp_relay:spawn_link({InSocket, OutSocket}, {ClientName, EndpointName}),
          eproxy_tcp_relay:spawn_link({OutSocket, InSocket}, {EndpointName, ClientName}),
          {next_state, relaying, State#state{
            negotiator = undefined,
            controlling_socket = undefined
          }}
      end
  end;

handle_request(bind, {DestAddress, DestPort}, #state{controlling_socket = InSocket, negotiator = Slave, client_name = ClientName} = State) ->
  BindAddress =
    case tuple_size(DestAddress) of
      4 -> eproxy_config:get_external_ipv4();
      8 -> eproxy_config:get_external_ipv6()
    end,
  case gen_tcp:listen(0, [binary, {nodelay, true}, {ip, BindAddress}, {active, false}]) of
    {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
    {ok, OutSocket} ->
      case inet:sockname(OutSocket) of
        {error, Reason} -> ?REPLY_AND_STOP(InSocket, general_failure, {failed_to_open_out_socket, Reason}, State);
        {ok, {BindAddress, BindPort} = AP} ->
          lager:info("~s has been provided with ~s for BINDing", [ClientName, eproxy:ap_as_string(AP)]),
          ok = socks5:send_reply(InSocket, succeeded, {BindAddress, BindPort}),
          Slave ! {accept_connection_from, OutSocket, {DestAddress, DestPort}},
          {next_state, accept, State, ?ACCEPT_TIMEOUT_MS}
      end
  end;

handle_request(udp_associate, {DestAddress, DestPort}, #state{controlling_socket = ControlSocket, negotiator = Slave} = State) ->
  {InternalAddress, ExternalAddress} =
    case tuple_size(DestAddress) of
      4 -> {eproxy_config:get_external_ipv4(), eproxy_config:get_external_ipv4()};
      8 -> {eproxy_config:get_external_ipv6(), eproxy_config:get_external_ipv6()}
    end,
  case gen_udp:open(0, [binary, {ip, InternalAddress}, {active, false}]) of
    {error, Reason} -> ?REPLY_AND_STOP(ControlSocket, general_failure, {failed_to_open_udp_relay, Reason}, State);
    {ok, InUdpSocket} ->
      case inet:sockname(InUdpSocket) of
        {error, Reason} -> ?REPLY_AND_STOP(ControlSocket, general_failure, {failed_to_open_udp_relay, Reason}, State);
        {ok, {InRelayAddress, InRelayPort}} ->
          case gen_udp:open(0, [binary, {ip, ExternalAddress}, {active, false}]) of
            {error, Reason} ->
              gen_udp:close(InUdpSocket),
              ?REPLY_AND_STOP(ControlSocket, general_failure, {failed_to_open_udp_relay, Reason}, State);
            {ok, OutUdpSocket} ->
              ok = socks5:send_reply(ControlSocket, succeeded, {InRelayAddress, InRelayPort}),
              Slave ! stop,
              eproxy_udp_relay:spawn_link(in, InUdpSocket, OutUdpSocket, {DestAddress, DestPort}),
              eproxy_udp_relay:spawn_link(out, OutUdpSocket, InUdpSocket, {DestAddress, DestPort}),
              inet:setopts(ControlSocket, [{active, true}]), %% to be notifyied with {tcp_closed, ControlSocket}
              {next_state, relaying, State#state{negotiator = undefined}}
          end
      end
  end.