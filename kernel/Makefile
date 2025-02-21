CC=gcc
CFLAGS=-c -g

all: slab_test

slab_test: slab_test.o slab_glue.o
	gcc -o $@ $^

.PHONY: clean
clean:
	rm -f slab_test slab_test.o slab_glue.o
