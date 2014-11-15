-module(eproxy).
-author(alex_burkov).

-export([
  start/0
]).


start() ->
  application:start(eproxy).
