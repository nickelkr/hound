/*
 *  This is just experimenting with pcap and the
 *  information found at: http://www.tcpdump.org/pcap.html
 */
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/in.h>

typedef char err[PCAP_ERRBUF_SIZE];

#define ETHER_ADDR_LEN 6

    // Ethernet header
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address
        u_char ether_shost[ETHER_ADDR_LEN]; // Source host address
        u_short ether_type; // IP? ARP? RARP? etc…
    };

    // IP Header
    struct sniff_ip {
        u_char ip_vhl;          // version << 4 | header length >> 2
        u_char ip_tos;          // type of service
        u_short ip_len;         // total length
        u_short ip_id;          // identification
        u_short ip_off;         // fragment offset field
    #define IP_RF 0x8000        // reserved fragment flag
    #define IP_DF 0x4000        // dont fragment flag
    #define IP_MF 0x2000        // more fragments flag
    #define IP_OFFMASK 0x1fff   // mask for fragmenting bits
        u_char ip_ttl;          // time to live
        u_char ip_p;            // protocol
        u_short ip_sum;         //checksum
        struct in_addr ip_src,ip_dst; // source and dest address
    };
    #define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)  (((ip)->ip_vhl) >> 4)

    // TCP Header
    typedef u_int tcp_seq;

    struct sniff_tcp {
        u_short th_sport;   // source port
        u_short th_dport;   // dest port
        tcp_seq th_seq;     // sequence number
        tcp_seq th_ack;     // ack number
        u_char th_offx2;    // data offset, rsvd
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win; // window
        u_short th_sum; // checksum
        u_short th_urp; // urgent pointer
    };

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
#define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; // ethernet header
    const struct sniff_ip *ip; // ip header
    const struct sniff_tcp *tcp; // tcp header
    const u_char *payload; // packet payload

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("    * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("    * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
}

int main(int argc, char **argv) {
    err err;
    char *device;
    pcap_t *interface;              // Session to be sniffed
    struct pcap_pkthdr header;      // Packet information
    //const u_char *packet;           // Packet data

    device = pcap_lookupdev(err);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find a device: %s", err);
        return 2;
    }

    interface = pcap_open_live(device, BUFSIZ, 1, 1000, err);
    if (interface == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, err);
        return 2;
    }

    if (pcap_datalink(interface) != DLT_EN10MB) {
        fprintf(stderr, "Device %s isn't returning Ethernet headers.\n", device);
        return 2;
    }

    // get packets
    pcap_loop(interface, 10, got_packet, NULL);
    pcap_next(interface, &header);
    printf("Packet intercepted with length: %d\n", header.len);
    //close it up
    pcap_close(interface);
    return 0;
}

