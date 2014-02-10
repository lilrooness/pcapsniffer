#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define ETHER_ADD_LEN 6

void hande_ip(const u_char *packet);

int main(int argc, char **argv) {
	
	if(argc < 2) {
		printf("USAGE= ./sniff [DEVICE]\n");
		return 1;
	}

	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = argv[1];
	const u_char *packet;
	struct ether_header *ethdr;
	u_char *host;

	pcap_t *handle;

	if(dev == NULL) {
		fprintf(stderr, "Default device not found: %s", errbuf);
		return 2;
	}

	printf("Using Device: %s\n", dev);

	handle = pcap_open_live(dev, 4096, 1, 3000, errbuf);

	if(handle == NULL) {
		fprintf(stderr, "Could not open device %s: %s", dev, errbuf);
	}

	packet = pcap_next(handle, &header);
	printf("Length:	%d\n", header.len);

	ethdr = (struct ether_header*) packet;

	printf("Type: %x\n", ntohs(ethdr->ether_type));

	int c=0;
	printf("dhost:	");
	for(c = 0; c < 6; c++) {
		printf("%x.", ethdr->ether_dhost[c]);
	}
	printf("\n");

	printf("shost:	");
	for(c = 0; c < 6; c++) {
		printf("%x.", ethdr->ether_shost[c]);
	}
	printf("\n");

	printf("Payload:\n\n");

	int i = 0;
	for(i=0; i<header.len; i++) {
		if(isprint(packet[i])) {
			printf("%c ", packet[i]);
		} else {
			printf("%d ", packet[i]);
		}
		if(i % 16 == 0 && i > 0) {
			printf("\n");
		}
	}
	printf("\n");

	//HANDLE IP PACKET
	if(ntohs(ethdr->ether_type) == 0x800) {
		hande_ip(packet);
	}
 
	return 0;
}

void hande_ip(const u_char *packet) {
	struct ip *ip_packet;
	ip_packet = (struct ip*) (packet + sizeof(struct ether_header));
	char *src = inet_ntoa(ip_packet->ip_src);
	printf("IP Source: %s\n", src);
	char *dest = inet_ntoa(ip_packet->ip_dst);
	printf("IP Dest: %s\n", dest);

	printf("\n");

	int dataLen = ip_packet->ip_len - ip_packet->ip_hl;
	// u_char *dataBegin = packet + sizeof(struct ether_header) + ip_packet->ip_hl;
	
	handle_tcp(packet);

	int i = 0;
	for(i=0; i<dataLen; i++) {
		if(isprint(*((packet + sizeof(struct ether_header) + ip_packet->ip_hl + sizeof(struct tcphdr)) + i))) {
			printf("%c ", *((packet + sizeof(struct ether_header) + ip_packet->ip_hl + sizeof(struct tcphdr)) + i));
			if(i % 16 == 0 && i > 0) {
				printf("\n");
			}
		} else {
			// printf("%d ", *((packet + sizeof(struct ether_header) + ip_packet->ip_hl) + i));
		}
	}
	printf("\n");
}

void handle_tcp(const u_char *packet) {
	struct tcphdr *tcp_packet = (struct tcphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
	printf("Destination port: %d\n", tcp_packet->th_dport);
	printf("Source port: %d\n", tcp_packet->th_sport);
}

