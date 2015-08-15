
CC=g++
CFLAGS=-I ../../ -DTEST_CLIENT
OBJS+=../mylib/Sockcli.o
OBJS+=../mylib/Timer.o
OBJS+=../mylib/Thread.o
OBJS+=../mylib/TcpTestClient.o
OBJS+=testcli.o

testcli: test.cpp $(OBJS)
	$(CC) $(CFLAGS) $^ -lpthread -lrt -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f *.o ../mylib/*.o testcli
