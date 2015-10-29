/*
 *  This is just experimenting with pcap and the
 *  information found at: http://www.tcpdump.org/pcap.html
 */
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>

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

void print_line(const u_char *payload, int len, int offset) {

    // print the offset
    printf("        %05d    ", offset);

    //print the line
    for(int i = 0; i < len; i++) {
        if (isprint(*payload))
            printf("%c", *payload);
        else
            printf("-");
        payload++;
    }
    printf("\n");
}

void print_payload(const u_char *payload, int size) {
    int rem = size;         // remaining number of bytes to print
    int width = 16;         // print width
    int len;                // keeping track of the print length
    int offset = 0;
    const u_char *ch = payload;

    // ensure we actually have something to print
    if (size <= 0)
        return;

    // print all the data if it is <= width
    if (size <= width) {
        print_line(ch, size, offset);
        return;
    }

    // print multi-line data
    while(1) {
        // get line length
        len = width % rem;
        print_line(ch, len, offset);
        // get remaining
        rem = rem - len;
        // shift pointer past what we've printed
        ch = ch + len;
        // set the offset
        offset = offset + width;
        // print again if we have width or less left
        if ( rem <= width) {
            print_line(ch, rem, offset);
            break;
        }
    }

    return;
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
#define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; // ethernet header
    const struct sniff_ip *ip; // ip header
    const struct sniff_tcp *tcp; // tcp header
    const u_char *payload; // packet payload

    int size_ip;
    int size_tcp;
    int size_payload;

    // cast ether struct over packet bytes
    ethernet = (struct sniff_ethernet*)(packet);

    // cast ip struct over packet bytes
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("    * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // give out the src and dst
    printf("    %s to %s", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

    // check the protocol
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("    TCP continuing\n");
            break;
        case IPPROTO_UDP:
            printf("    UDP bailing\n");
            return;
        case IPPROTO_ICMP:
            printf("    ICMP bailing\n");
            return;
        case IPPROTO_IP:
            printf("    IP bailing\n");
            return;
    }

    // now we know the packet is TCP
    // cast tcp struct over packet bytes
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("    * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("      From port: %d to port: %d\n", tcp->th_sport, tcp->th_dport);

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    // print the payload
    printf("      Payload size: %d\n", size_payload);
    print_payload(payload, size_payload);
}

int main(int argc, char **argv) {
    err err;
    char *device;                   // device name
    pcap_t *interface;              // capture handle

    char filter[] = "ip";           // we want to filter everything but IP packets
    struct bpf_program cf;          // compiled filter
    bpf_u_int32 mask;               // subnet mask
    bpf_u_int32 net;                // ip address
    int p_count = 10;                    // num of packets to intercept

    // get a device to listen on
    device = pcap_lookupdev(err);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find a device: %s", err);
        return 2;
    }

    // get the ip address and mask
    if (pcap_lookupnet(device, &net, &mask, err) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s", device, err);
        net = 0;
        mask = 0;
    }

    printf("Listening on %s for %d packets with filter: %s\n", device, p_count, filter);

    // open the device for listening
    interface = pcap_open_live(device, BUFSIZ, 1, 1000, err);
    if (interface == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, err);
        return 2;
    }

    // Ensure we're listening to Ethernet traffic
    if (pcap_datalink(interface) != DLT_EN10MB) {
        fprintf(stderr, "Device %s isn't returning Ethernet headers.\n", device);
        return 2;
    }

    // compile the filter expression
    if (pcap_compile(interface, &cf, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't compile filter %s: %s\n", filter, pcap_geterr(interface));
        exit(1);
    }

    // apply the compiled filter
    if (pcap_setfilter(interface, &cf) == -1) {
        fprintf(stderr, "Couldn't apply filter %s: %s\n", filter, pcap_geterr(interface));
        exit(1);
    }

    // get some packets!
    pcap_loop(interface, p_count, got_packet, NULL);

    // a little house cleaning
    pcap_freecode(&cf);
    pcap_close(interface);

    printf("All done.\n");

    return 0;
}

