CC=gcc
FLAGS=-Iheader -Wall

all: purenc purdec

purdec: src/purdec.c
	$(CC) $(FLAGS) -o purdec src/purdec.c

purenc: src/purenc.c
	$(CC) $(FLAGS) -o purenc src/purenc.c

.PHONY: clean
clean:
	rm purdec purenc