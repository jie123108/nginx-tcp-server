
CC=g++

OBJS+=../mylib/Sockcli.o
OBJS+=../mylib/Timer.o
OBJS+=../mylib/Thread.o
OBJS+=../mylib/TcpTestClient.o
OBJS+=testcli.o

testcli: test.cpp $(OBJS)
	$(CC) $^ -lpthread -lrt -o $@

%.o: %.cpp
	$(CC) -c $^ -o $@

clean:
	rm -f *.o testcli
