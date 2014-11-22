default: compile

.PHONY: compile test

compile:
	rebar compile

clean:
	rebar clean

test: compile
	test/acceptence.escript

dialyze:
	dialyzer -pa deps/lager/ebin -I deps/lager/include ebin/*.beam

dante:
	dante-1.4.1/sockd/sockd -p sockd.pid -f sockd.conf -D

1080:
	netstat -tna | grep 1080 || true