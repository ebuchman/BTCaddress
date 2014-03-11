SRC=./src/
INCLUDE=-I./include/
CFLAGS=-Wno-deprecated-declarations
LIB=-L/opt/local/lib -L/Library/Frameworks/EPD64.framework/Versions/Current/lib/python2.7/config/ 

all:
	gcc $(CFLAGS) $(LIB) -lssl -lgmp -lcrypto -lpython2.7 -lm -o crypt $(SRC)addrgen.c $(SRC)crypto.c $(SRC)encoding.c $(SRC)rng.c $(INCLUDE) 
