#!/bin/bash

#curl --socks5 183.90.187.93:1080 ya.ru > /dev/null 
echo -en "\x05\x08\x00\x01\x02\x03\x7f\x80\xfe\xff"\
"\x05\x01\x00\x01\xef" | nc localhost 1080
