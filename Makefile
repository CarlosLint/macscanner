CC=gcc
CFLAGS=-O2

.SUFFIXES: .c .asm
.c.o:
	$(CC) $(CFLAGS) -c $<


SRC = macscanner.c
OBJ = macscanner.o
BIN = macscanner

all:	macscanner

macscanner:
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

clean:
	rm -f $(OBJ) $(BIN)
