#include <stdio.h>
#include <pcap/pcap.h>

pcap_if_t* getDevices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces = NULL;

    // find all of the devices on the machine
    int code = pcap_findalldevs(&interfaces, errbuf);

    // check the codes to ensure we didn't receive an error
    // error received and should be in errbuf
    if (code == -1) {
        printf("Error: %s\n", errbuf);
    } else if (code != 0) {
        printf("Uknown code received: %d\n", code);
    }

    return interfaces;
}

int main() {
    printf("Welcome to Hound\n");




    return 0;
}

