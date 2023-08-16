LDLIBS += -lnetfilter_queue

all: netfilter-test

netfilter-test: netfilter-test.c

clean:
	rm -f netfilter-test *.o

