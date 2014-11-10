CXX?=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall

debug: CFLAGS += -g
debug: all

all: client server

client:
	$(CXX) $(CFLAGS) client.cpp $(LFLAGS) -o client

server:
	$(CXX) $(CFLAGS) server.cpp $(LFLAGS) -o server

clean:
	rm client
	rm server