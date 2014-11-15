-module(eproxy_sup).
-author(alex_burkov).
-behaviour(supervisor).

-export([
  start_link/0,
  init/1
]).

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  {ok, {{one_for_one, 3, 1}, [
    {router,     {router,     start_link, []}, permanent, 5000, worker,     [router]},
    {client_sup, {client_sup, start_link, []}, permanent, 5000, supervisor, [client_sup]}
  ]}}.

