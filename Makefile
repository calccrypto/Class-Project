# Class Project Makefile
CXX?=g++
CFLAGS=-std=c++11 -Wall
LFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L../OpenPGP -lpthread
TARGET=kerberos

debug: CFLAGS += -g
debug: all

all: $(TARGET)

client.o: client.cpp shared.h ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c client.cpp

server.o: server.cpp shared.h  user.h ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c server.cpp

shared.o: shared.h shared.cpp ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c shared.cpp

threaddata.o: threaddata.h threaddata.cpp user.h
	$(CXX) $(CFLAGS) -c threaddata.cpp

user.o: user.h user.cpp ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c user.cpp

$(TARGET): shared.o client.o server.o user.o threaddata.o
	$(CXX) $(CFLAGS) client.o shared.o $(LFLAGS) -o client
	$(CXX) $(CFLAGS) server.o shared.o user.o threaddata.o $(LFLAGS) -o server

clean:
	rm -f client
	rm -f server
	rm -f *.o
