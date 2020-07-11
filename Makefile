.PHONY: all
all: any2tcp any2udp

any2tcp: any2tcp.c
	gcc any2tcp.c -lnetfilter_queue -o any2tcp

any2udp: any2udp.c
	gcc any2udp.c -lnetfilter_queue -o any2udp

.PHONY: clean
clean:
	rm -f any2tcp any2udp