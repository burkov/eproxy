-module(client_sup).
-author(alex_burkov).

-behaviour(supervisor).

-export([
  start_link/0,
  start_client/1,
  init/1
]).

-define(SERVER, ?MODULE).

start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_client(ClientSocket) ->
  supervisor:start_child(?SERVER, [ClientSocket]).

init([]) ->
  {ok, {{simple_one_for_one, 0, 1}, [
    {not_used, {client, start_link, []}, temporary, 2000, worker, [client]}
  ]}}.
