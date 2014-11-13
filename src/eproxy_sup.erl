-author(alex_burkov).
-module(eproxy_sup).
-behaviour(supervisor).

-export([
  start_link/0,
  init/1
]).

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  {ok, {{one_for_one, 0, 1}, [
%%     {I, {I, start_link, []}, permanent, 5000, Type, [I]}
  ]}}.

