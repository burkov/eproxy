-module(eproxy).
-author(alex_burkov).

%%% Module this misc. functions

-export([
  start/0,
  peername_as_string/1,
  sockname_as_string/1,
  ap_as_string/1
]).

-spec start() -> ok.
%% @doc shorthand for application starup
start() -> application:start(eproxy).

-spec peername_as_string(gen_tcp:socket() | gen_udp:socket()) -> string().
%% @doc returns peername of given socket as a string in format "<ip address>:<port>"
peername_as_string(Socket) ->
  {ok, AP} = inet:peername(Socket),
  ap_as_string(AP).

-spec sockname_as_string(gen_tcp:socket() | gen_udp:socket()) -> string().
%% @doc returns sockname of given socket as a string in format "<ip address>:<port>"
sockname_as_string(Socket) ->
  {ok, AP} = inet:sockname(Socket),
  ap_as_string(AP).

-spec ap_as_string({inet:ip_address(), inet:port_number()}) -> string().
%% @doc converts given pair of {ip, port} into a string in format "<ip address>:<port>"
ap_as_string({A, P}) when is_tuple(A) -> io_lib:format("~s:~p", [inet:ntoa(A), P]);
ap_as_string({A, P}) when is_list(A) -> io_lib:format("~s:~p", [A, P]).


