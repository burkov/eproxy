-module(eproxy_app).
-author(alex_burkov).
-behaviour(application).

-export([
  start/2,
  stop/1
]).

start(_StartType, _StartArgs) -> eproxy_sup:start_link().
stop(_State) -> ok.
