#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/* IP Header */
struct ipheader {
    unsigned char ihl:4,      // IP header length
                  version:4;  // IP version
    unsigned char tos;        // Type of service
    unsigned short int len;   // IP Packet length (data + header)
    unsigned short int ident; // Identification
    unsigned short int flags:3,  // Fragmentation flags
                       offset:13; // Flags offset
    unsigned char ttl;        // Time to Live
    unsigned char protocol;   // Protocol type
    unsigned short int checksum; // IP datagram checksum
    struct in_addr sourceip;  // Source IP address
    struct in_addr destip;    // Destination IP address
};

/* TCP Header */
struct tcpheader {
    unsigned short int source;   // Source port
    unsigned short int dest;     // Destination port
    unsigned int seq;            // Sequence Number
    unsigned int ack_seq;        // Acknowledgement Number
    unsigned short int res1:4,   // Data offset, reserved
                       doff:4,
                       fin:1,    // Flags
                       syn:1,
                       rst:1,
                       psh:1,
                       ack:1,
                       urg:1,
                       ece:1,
                       cwr:1;
    unsigned short int window;   // Window
    unsigned short int checksum; // Checksum
    unsigned short int urg_ptr;  // Urgent pointer
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;

    if (ntohs(eth->h_proto) == ETH_P_IP) { // Check if it's an IP packet
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethhdr));

        if (ip->protocol == IPPROTO_TCP) { // Check if it's a TCP packet
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethhdr) + ip->ihl * 4);

            printf("Source Port: %d\n", ntohs(tcp->source));
            printf("Destination Port: %d\n", ntohs(tcp->dest));
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // Only capture TCP packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}
