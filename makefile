CC = g++ -std=c++11 -Wall
objs = server.o main.o client.o error.o
exec = main
libs = openssl

all:$(objs)
	$(CC) -o $(exec) $^ `pkg-config --libs $(libs)`

%.o:%.cpp
	$(CC) -c -o $@ $< `pkg-config --cflags $(libs)`

clean:
	rm $(exec) $(objs)

remake:
	make clean; make
