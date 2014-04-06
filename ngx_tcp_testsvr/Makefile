
CC=g++ -g

CFLAGS+=-I$(BASELIBDIR)
LDFLAGS=$(BASELIBDIR)/baselib.a -lrt
OBJS+=status_dao.o
#OBJS+=$(THMDIR)/thumbupload.o

all: blocktest

blocktest: BlockTest.cpp $(OBJS)
	$(CC) $(CFLAGS) $^  $(LDFLAGS) -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f *.o blocktest


