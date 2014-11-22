-module(eproxy_client_sup).
-author(alex_burkov).

-behaviour(supervisor).

-export([
  start_link/0,
  serve_client/1,
  init/1
]).

-define(SERVER, ?MODULE).

start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).

serve_client(ClientSocket) ->
  supervisor:start_child(?SERVER, [ClientSocket]).

init([]) ->
  %% eproxy_client is highly unrelaible actor, it can crash easily but shouldn't affect its neighbours
  {ok, {{simple_one_for_one, 0, 1}, [
    {eproxy_client, {eproxy_client, start_link, []}, temporary, 2000, worker, [eproxy_client]}
  ]}}.
