.PHONY: all clean
all: crypto test
clean:
	rm -f *.o decrypt encrypt test
crypto.o: crypto.c
	gcc -Wall -c crypto.c
tests.o: tests.c
	gcc -Wall -c tests.c
main.o: main.c
	gcc -Wall -c main.c
crypto: crypto.o main.o
	gcc -o encrypt crypto.o main.o
	gcc -o decrypt crypto.o main.o
test: crypto.o tests.o
	gcc -o tests tests.o crypto.o
	./tests