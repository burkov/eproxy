-module(client).
-author(alex_burkov).

-behaviour(gen_fsm).

-export([
  start_link/1,
  init/1,
  auth_method_selection/2,
  auth_method_selection/3,
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
-define(AUTH_SUBROUTINE_TIMEOUT_MS, 2000).

-record(state, {
  socket :: gen_tcp:socket(),
  slave :: pid()
}).


start_link(Socket) ->
  gen_fsm:start_link(?MODULE, [Socket], []).

init([Socket]) ->
  {ok, {Address, Port}} = inet:peername(Socket),
  lager:debug("client connected, socket: ~p:~p", [inet:ntoa(Address), Port]),

%%   Slave = erlang:spawn(?MODULE, slave, [self(), Socket]),
%%   Slave ! recv_auth_method_selection,
  inet:setopts(Socket, [{active, true}]),
  Slave = 42,
  {ok, auth_method_selection, #state{socket = Socket, slave = Slave}, ?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS}.

%%% auth method selection

auth_method_selection({auth_methods, AuthMethods}, #state{socket = Socket, slave = Slave} = State) ->
  case select_supported_auth_method(AuthMethods) of
    none ->
      lager:debug("none of auth methods passed is supported by server"),
      send_method_selection_reject(Socket),
      {stop, normal, State};
    Method ->
      lager:debug("selected auth method: '~p'. proceeding to authentication subroutine", [Method]),
      Slave ! {do_authentication, Method},
      {next_state, request, State, ?AUTH_SUBROUTINE_TIMEOUT_MS}
  end;

auth_method_selection(timeout, State) ->
  lager:warning("auth method negotiation took too long (> ~p ms), exiting", [?AUTH_METHOD_NEGOTIATION_TIMEOUT_MS]),
  {stop, auth_method_selection_timeout, State}.

auth_method_selection(Event, _From, State) ->
  lager:warning("unexpected sync event ~p", [Event]),
  {stop, unsupported_sync_event, State}.

%%% request

request(timeout, State) ->
  lager:warning("authentication took too long (> ~p ms), exiting", [?AUTH_SUBROUTINE_TIMEOUT_MS]),
  {stop, authentication_subroutine_timeout, State};

request(Event, State) ->
  lager:warning("unexpected event ~p", [Event]),
  {next_state, request, State}.

request(Event, _From, State) ->
  lager:warning("unexpected sync event ~p", [Event]),
  {stop, unsupported_sync_event, State}.

%%% template

state_name(Event, State) ->
  lager:warning("unexpected event ~p", [Event]),
  {next_state, state_name, State}.

state_name(Event, _From, State) ->
  lager:warning("unexpected sync event ~p", [Event]),
  {reply, {error, unsupported}, state_name, State}.

%%%

handle_event({stop, Reason}, StateName, State) ->
  lager:warning("stopped in state '~p', reason: ~p", [StateName, Reason]),
  {stop, Reason, State};

handle_event(Event, _StateName, State) ->
  lager:warning("unexpected all state event ~p", [Event]),
  {stop, unsupported_all_state_event, State}.

handle_sync_event(Event, _From, _StateName, State) ->
  lager:warning("unexpected all state sync event ~p", [Event]),
  {stop, unsupported_all_state_sync_event, State}.

%%% handle_info

handle_info(Info, _StateName, State) ->
  lager:warning("unexpected info ~p", [Info]),
  {stop, unsupported_info, State}.

terminate(Reason, StateName, #state{socket = Socket}) ->
  gen_tcp:close(Socket),
  lager:warning("termination in state '~p', reason: ~p", [StateName, Reason]).

code_change(_OldVsn, StateName, State, _Extra) ->
  {ok, StateName, State}.

select_supported_auth_method(MethodsBin) ->
  ClientMethodsSet = sets:from_list([socks5:auth_method(X) || <<X>> <= MethodsBin]),
  ServerMethodsSet = config:get_auth_methods(),
  case sets:to_list(sets:intersection(ClientMethodsSet, ServerMethodsSet)) of
    [] -> none;
    [OnlyOne] -> OnlyOne;
    MoreThanOne -> select_preferred_auth_method(MoreThanOne)
  end.

send_method_selection_reject(Socket) ->
  lager:debug("rejecting client method selection"),
  gen_tcp:send(Socket, <<?VERSION_SOCKS5:8, ?NO_ACCEPTABLE_MATHODS:8>>).

select_preferred_auth_method(ListOfMethods) ->
  case lists:member(no_auth, ListOfMethods) of
    true -> no_auth;
    false -> none
  end.

%%% slave actor

-define(VALIDATE(Name, Term),
  try
    Term
  catch throw:{Type, Value} ->
    lager:warning(Name ++ " validation failed, caught '~p' (~p)", [Type, Value]),
    stop(Master, Type),
    exit(normal)
  end
).

slave(M, S) ->
  erlang:link(M), %% crash master on fail, and get crashed by master in case of its failure
%%   erlang:monitor(process, M),
  fun Recur(Master, Socket) ->
    receive
%%       {'DOWN', _Mref, process, Master, Reason} ->
%%         lager:debug("master is down with reason: ~p, exiting", [Reason]),
%%         exit(normal);
      recv_auth_method_selection ->
        {ok, <<ProtocolVersion:8, MethodsCount:8>>} = gen_tcp:recv(Socket, 2, ?RECV_TIMEOUT_MS),
        ?VALIDATE("auth method negotiation",
          throw_if(ProtocolVersion =/= ?VERSION_SOCKS5, {unsupported_socks_version, ProtocolVersion})
        ),
        lager:debug("protocol socks5, fetching supported auth methods list (~p items)", [MethodsCount]),
        {ok, Methods} = gen_tcp:recv(Socket, MethodsCount, ?RECV_TIMEOUT_MS),
        gen_fsm:send_event(Master, {auth_methods, Methods});
      {do_authentication, no_auth} ->
        %% nothing to do
        lager:debug("authntication complete (~p)", [no_auth]),
        self() ! recv_request;
      {do_authentication, AuthMethod} ->
        lager:error("unsupported auth method '~p'", [AuthMethod]),
        send_method_selection_reject(Socket),
        stop(Master, auth_method_not_supported);
      recv_request ->
        {ok, <<ProtocolVersion:8, Command:8, Reserved:8, AType:8>>} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
        CommandName = socks5:command(Command),
        AddressTypeName = socks5:address_type(AType),
        ?VALIDATE("client request",
          begin
            throw_if(ProtocolVersion =/= ?VERSION_SOCKS5, {unsupported_socks_version, ProtocolVersion}),
            throw_if(CommandName =:= invalid_command, {unsupported_command, CommandName}),
            warn_if(Reserved =/= ?RESERVED, "reserved =/= ~p", [?RESERVED]),
            throw_if(AddressTypeName =:= invalid_address_type, {unsupported_address_type, AddressTypeName})
          end
        ),
        lager:debug("got command '~p', fetching address type of '~p'", [CommandName, AddressTypeName]),
        Address =
          case AddressTypeName of
            ipv4 ->
              {ok, Binary} = gen_tcp:recv(Socket, 4, ?RECV_TIMEOUT_MS),
              list_to_tuple([X || <<X>> <= Binary]);
            ipv6 ->
              {ok, Binary} = gen_tcp:recv(Socket, 16, ?RECV_TIMEOUT_MS),
              list_to_tuple([X || <<X:16>> <= Binary]);
            domain_name ->
              {ok, Length} = gen_tcp:recv(Socket, 1, ?RECV_TIMEOUT_MS),
              {ok, DomainName} = gen_tcp:recv(Socket, Length, ?RECV_TIMEOUT_MS),
              DomainName
          end,
        lager:debug("address = ~p", [Address]);
      Else ->
        lager:warning("unknown command (~p), exiting", [Else])
    end,
    Recur(Master, Socket)
  end(M, S).


%%% helpers

throw_if(Predicate, Type) ->
  case Predicate of
    true -> throw(Type);
    false -> ok
  end.

warn_if(Predicate, Format, Args) ->
  case Predicate of
    true -> lager:warning(Format, Args);
    false -> ok
  end.


stop(Master, Reason) ->
  gen_fsm:send_all_state_event(Master, {stop, Reason}).



