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

$(TARGET): client.cpp server.cpp OpenPGP
	$(CXX) $(CFLAGS) client.cpp $(LFLAGS) -o client
	$(CXX) $(CFLAGS) server.cpp $(LFLAGS) -o server

clean:
	rm client
	rm server