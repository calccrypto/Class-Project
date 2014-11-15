# Class Project Makefile

CXX?=g++
CFLAGS=-std=c++11 -Wall
LFLAGS=-lOpenPGP -lgmp -lgmpxx -lbz2 -lz -L../OpenPGP
TARGET=kerberos

debug: CFLAGS += -g
debug: all

all: $(TARGET)

.PHONY: OpenPGP

OpenPGP:
	$(MAKE) -C ../OpenPGP

user.o: user.h user.cpp ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c user.cpp

client.o: client.cpp shared.h ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c client.cpp 

server.o: server.cpp shared.h user.h 
	$(CXX) $(CFLAGS) -c server.cpp 
    
shared.o: shared.h shared.cpp ../OpenPGP/OpenPGP.h
	$(CXX) $(CFLAGS) -c shared.cpp

$(TARGET): shared.o client.o server.o 
	$(CXX) $(CFLAGS) client.o shared.o $(LFLAGS) -o client
	$(CXX) $(CFLAGS) server.o shared.o user.o $(LFLAGS) -o server

clean:
	rm client
	rm server
	$(MAKE) -C ../OpenPGP clean