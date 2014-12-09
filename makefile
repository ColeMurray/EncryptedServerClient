# MakeFile for CS165 OpenSSL File Server
#Compiler
CC=gcc
CFLAGS=-ggdb 
LDFLAGS = -I /usr/include/openssl/ 
LIBS= -lssl -lcrypto
EXECUTABLES: client server

all: $(EXECUTABLES)

client: client.c 
	$(CC) $(CFLAGS)  client.c $(LIBS)  -o client 
server: server.c
	$(CC) $(CFLAGS) server.c $(LIBS) -o server

clean:
	rm -rf client server
