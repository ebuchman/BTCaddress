SRC=./src/
INCLUDE=-I./include/
CFLAGS=-Wno-deprecated-declarations
all:
	gcc $(CFLAGS) -lssl -L/opt/local/lib -lgmp -lcrypto -o crypt $(SRC)addrgen.c $(SRC)crypto.c $(SRC)encoding.c $(INCLUDE) 
