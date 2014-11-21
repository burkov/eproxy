#!/bin/bash

erl -pa ebin deps/*/ebin -config priv/sys.config -s lager -s eproxy -noshell
