CC=gcc
FLAGS=-Iheader -Wall

all: purenc purdec

purdec: src/purdec.c src/shared.c header/purdec.h
	$(CC) $(FLAGS) -o purdec src/purdec.c -lgcrypt

purenc: src/purenc.c src/shared.c header/purenc.h
	$(CC) $(FLAGS) -o purenc src/purenc.c -lgcrypt

.PHONY: clean
clean:
	rm purdec purenc