CXX?=g++
LFLAGS=
CFLAGS=-std=c++11 -Wall

debug: CFLAGS += -g
debug: all

all:
	$(CXX) $(CFLAGS) client.cpp $(LFLAGS) -o client
	$(CXX) $(CFLAGS) server.cpp $(LFLAGS) -o server

clean:
	rm client
	rm server