CC=gcc
RM=rm -f
CFLAGS=-Wall -Werror -pedantic -pipe

TARGETS=elf elf2
OBJFILES=bso.o

all: $(TARGETS)

clean:
	$(RM) $(TARGETS) $(OBJFILES)

elf: elf.c $(OBJFILES)
	$(CC) $(CFLAGS) -s -o elf elf.c $(OBJFILES)

elf2: elf2.c $(OBJFILES)
	$(CC) $(CFLAGS) -s -o elf2 elf2.c $(OBJFILES)

bso.o: bso.c bso.h
	$(CC) $(CFLAGS) -o bso.o -c bso.c

