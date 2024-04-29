CC=gcc
FLAGS=-Iheader -Wall

all: purenc purdec

purdec: src/purdec.c
	$(CC) $(FLAGS) -o purdec src/purdec.c -lgcrypt

purenc: src/purenc.c
	$(CC) $(FLAGS) -o purenc src/purenc.c -lgcrypt

.PHONY: clean
clean:
	rm purdec purenc