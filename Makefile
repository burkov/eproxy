default: compile

.PHONY: compile test

compile:
	rebar compile

test: compile
	test/acceptence.escript

dialyze:
	dialyzer -pa deps/lager/ebin -I deps/lager/include ebin/*.beam