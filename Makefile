.PHONY: all clean deps compile run

all: deps compile

clean:
	rm -f ctrie

deps:
	make -C deps/fnv

compile:
	gcc ctrie.c -ggdb3 -W -Wall -DCTRIE32 -I deps/fnv/ -L deps/fnv/ -lfnv -o ctrie
run:
	gcc ctrie.c -ggdb3 -W -Wall -DCTRIE32 -I deps/fnv/ -L deps/fnv/ -lfnv -o ctrie
	./ctrie
