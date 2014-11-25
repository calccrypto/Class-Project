# Kerberos based communication project

Copyright (c) 2014 Omar Azhar
Copyright (c) 2014 Jason Lee @ calccrypto at gmail.com

Please see LICENSE file for license. The networking code
was modified from code written by Andrew Zonenberg.

## IMPORTANT
**This code was not written for actual use.**

**It is the final project for our Fall 2014 Computer Security course, nothing more.**

- POSIX libraries are required for sockets.
- C++11 threads are used instead of POSIX.
- --curlcpp (<https://github.com/JosephP91/curlcpp>) is needed to get the client's ip address--
  - --curl, required by curlcpp (<http://curl.haxx.se/>, `sudo apt-get install libcurl-devel`, etc)--
  - --In `curlcpp/`, run `cmake CmakeLists.txt && make` to build--
  - currently don't need due to localhost being sent to server as client IP address
- OpenPGP (https://github.com/calccrypto/OpenPGP), and its dependencies:
  - GMP (<https://gmplib.org/>, `sudo apt-get install libdev-gmp`, etc)
  - bzip2 (<http://www.bzip.org/>, `sudo apt-get install libbz2-dev`, etc)
  - zlib (<http://www.zlib.net/>, `sudo apt-get install zlib1g-dev`, etc)
  - In `OpenPGP/`, run `make` to build library

The makefile assumes that the folder containing this
project is in the same directory as OpenPGP and curlcpp.

Once all of the necessary files are available, run
make to build the server and client programs.
