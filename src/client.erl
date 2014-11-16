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

-define(VERSION_SOCKS5, 5).
-define(RECV_TIMEOUT_MS, 1000).

-record(state, {
  socket :: gen_tcp:socket()
}).

start_link(Socket) ->
  gen_server:start_link(?MODULE, [Socket], []).

init([Socket]) ->
  lager:debug("client started, socket: ~p", [Socket]),
  gen_server:cast(self(), method_selection),
  {ok, #state{socket = Socket}}.

handle_call(Request, _From, State) ->
  lager:warning("unexpected call ~p", [Request]),
  {reply, ok, State}.

handle_cast(method_selection, #state{socket = Socket} = State) ->
  {ok, <<ProtocolVersion:8, MethodsCount:8>>} = gen_tcp:recv(Socket, 2, ?RECV_TIMEOUT_MS),
  case ProtocolVersion of
    ?VERSION_SOCKS5 ->
      lager:debug("protocol socks5, fetching supported auth methods list (~p items)", [MethodsCount]),
      {ok, Methods} = gen_tcp:recv(Socket, MethodsCount, ?RECV_TIMEOUT_MS);
    Other ->
      lager:warning("unsupported protocol version ~p", [Other])
  end,
  {noreply, State};

handle_cast(Request, State) ->
  lager:warning("unexpected cast ~p", [Request]),
  {noreply, State}.

handle_info(Info, State) ->
  lager:warning("unexpected info ~p", [Info]),
  {noreply, State}.

terminate(Reason, #state{socket = Socket}) ->
  gen_tcp:close(Socket),
  lager:warning("termination, reason:~p", [Reason]).

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

are_auth_methods_supported(Methods) ->
  true.

