
all: robocfg

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $^

robocfg: robocfg.o
	$(CC) -o $@ $^ $(LDFLAGS) -lbcm53xx

clean:
	rm -f *.o robocfg
