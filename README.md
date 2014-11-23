eproxy
======

A really simple SOCKS5 proxy written in Erlang 

- only no_auth authentication method is supported
- UDP ASSOCIATE re-fragmenting isn't supported

### Supervision tree

![alt text](https://raw.githubusercontent.com/burkov/eproxy/master/supervisors.png "supervisors")

### Build
just run `make`

### Start
use script `./start.sh`

### Test
run `make test`

