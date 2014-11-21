#!/usr/bin/env escript
%%! -pa ebin


main(_) ->
  Self = self(),
  io:format("~p~n", [Self]),
  erlang:spawn(fun() ->
    io:format("~p~n", [self()]),
    {ok, S} = gen_tcp:connect(localhost, 1080, [{active, false}]),
    Self ! S,
    {ok, _} = gen_tcp:recv(S, 42)
  end),
  receive S -> gen_tcp:close(S) end,
  timer:sleep(1000).


