CC       = gcc -traditional

CFLAGS= -O2 -g -DLINUX -DDEBUG -DSTANDALONE 
# for Linux
LDFLAGS= 
OBJS = telnetd.o logwtmp.o logout.o
# For Sun-OS
#LDFLAGS= -lrpcsvc -lkvm
#OBJS = getload.o telnetd.o logwtmp.o logout.o

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: telnetd
telnetd: $(OBJS)
	$(CC) $(CFLAGS) -o telnetd $(OBJS) $(LDFLAGS)

clean:
	rm -f *.o core telnetd
