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

user.o: user.h user.cpp OpenPGP
	$(CXX) $(CFLAGS) -c user.cpp $(LFLAGS)

$(TARGET): client.cpp server.cpp user.o OpenPGP
	$(CXX) $(CFLAGS) client.cpp $(LFLAGS) -o client
	$(CXX) $(CFLAGS) server.cpp user.o $(LFLAGS) -o server

clean:
	rm client
	rm server
	$(MAKE) -C ../OpenPGP clean