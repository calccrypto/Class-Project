# Kerberos based communication project

Copyright (c) 2014 Omar Azhar
Copyright (c) 2014 Jason Lee @ calccrypto at gmail.com

Please see LICENSE file for license. The networking code
was modified from code written by Andrew Zonenberg.

POSIX libraries are required for sockets.
C++11 threads are used instead of POSIX.
curlcpp (https://github.com/JosephP91/curlcpp) is needed to get the client's ip address.

OpenPGP (https://github.com/calccrypto/OpenPGP), and
its dependencies are required to build this project.
The makefile assumes that the folder containing this
project is in the same directory as OpenPGP.

Similarly, curlcpp should also be in the same directory
as this project and OpenPGP. Run cmake CmakeLists.txt && make
to build curlcpp.

Once all of the necessary files are available, run
make to build the server and client programs.

----

This is our final project for our Fall 2014 Computer Security
course.