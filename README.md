# Kerberos based communication project

Copyright (c) 2014 Omar Azhar
Copyright (c) 2014 Jason Lee @ calccrypto at gmail.com

Please see LICENSE file for license. The networking code
was modified from code written by Andrew Zonenberg.

POSIX libraries are required for sockets.
C++11 threads are used instead of POSIX.

OpenPGP (https://github.com/calccrypto/OpenPGP), and
its dependencies are required to build this project.
The makefile assumes that the folder containing this
project is in the same directory as OpenPGP. 

Once all of the necessary files are available, run
make to build the server and client programs. Build
OpenPGP if has not already been built.

----

This is our final project for our Fall 2014 Computer Security
course. 