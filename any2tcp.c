#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>

struct nfq_handle *h;
struct nfq_q_handle *qh;

// Calculate IPv4 checksum
static uint16_t calcIPv4checksum(unsigned char *payload) {
    uint32_t sum = 0;
    int i = 0;
    for (; i < 10; i += 2) {
        sum += (uint32_t)(((uint16_t)payload[i] << 8) | (uint16_t)payload[i+1]);
    }
    i += 2; // Skip checksum field
    for (; i < 20; i += 2) {
        sum += (uint32_t)(((uint16_t)payload[i] << 8) | (uint16_t)payload[i+1]);
    }
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + ((sum >> 16));
    }
    return ~((uint16_t)sum);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);

    unsigned char *payload;
    int ret = nfq_get_payload(nfa, &payload);
    if (ret >= 20) {
        printf("payload_len=%d - ", ret);
        printf("IP Protocol: 0x%X - ", payload[9]);
        printf("Checksum: 0x%02X%02X - ", payload[10], payload[11]);

        payload[9] = 0x06;
        
        uint16_t newChecksum = calcIPv4checksum(payload);
        printf("new checksum: 0x%04X - ", newChecksum);

        payload[10] = (newChecksum >> 8);
        payload[11] = (newChecksum & 0xFF);

        printf("\n");
	    return nfq_set_verdict(qh, id, NF_ACCEPT, ret, payload);
    }

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static void closeAll(int signo) {
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	printf("closing library handle\n");
	nfq_close(h);
    exit(0);
}

int main(int argc, char **argv) {
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    if (signal(SIGINT, closeAll) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		nfq_handle_packet(h, buf, rv);
	}

    closeAll(0);
}
