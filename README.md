# Kerberos based communication project

Copyright (c) 2014 Omar Azhar
Copyright (c) 2014 Jason Lee @ calccrypto at gmail.com

Please see LICENSE file for license. 
The networking code was modified from code written by Andrew Zonenberg.
The terminal echo on/off code is under the Creative Commons Attribution-ShareAlike 3.0 Unported license. Full description is provided above relavant code.

## IMPORTANT
**This code was not written for actual use.**

**It is the final project for our Fall 2014 Computer Security course, nothing more.**

## Requirements
- GCC 4.9.2 or equivalent
- POSIX libraries are required for sockets.
- C++11 threads are used instead of POSIX threads.
- OpenPGP (https://github.com/calccrypto/OpenPGP), and its dependencies:
  - GMP (<https://gmplib.org/>, `sudo apt-get install libdev-gmp`, etc)
  - bzip2 (<http://www.bzip.org/>, `sudo apt-get install libbz2-dev`, etc)
  - zlib (<http://www.zlib.net/>, `sudo apt-get install zlib1g-dev`, etc)
  - In `OpenPGP/`, run `make` to build library

The makefile assumes that the folder containing this
project is in the same directory as OpenPGP.

Once all of the necessary files are available, run make to build the server and client programs.
