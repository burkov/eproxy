#!/bin/bash


#while test -n "$(netstat -t4na | grep 1080)"; do
#    echo -n "."
#    sleep 1
#done

erl -pa ebin deps/*/ebin -config sys.config -s lager -s eproxy -noshell
