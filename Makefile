all: my_ping

my_ping:my_ping.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f *.o my_ping

