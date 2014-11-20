-module(eproxy_sup).
-author(alex_burkov).
-behaviour(supervisor).

-export([
  start_link/0,
  init/1
]).

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  %% rest_for_one - acceptor can crash, but it won't affect already opened socks connections
  {ok, {{rest_for_one, 3, 1}, [
    {eproxy_client_sup, {eproxy_client_sup, start_link, []}, permanent, 5000, supervisor, [eproxy_client_sup]},
    {eproxy_config,     {eproxy_config,     start_link, []}, permanent, 5000, worker,     [eproxy_config]},
    {eproxy_acceptor,   {eproxy_acceptor,   start_link, []}, permanent, 5000, worker,     [eproxy_acceptor]}
  ]}}.

