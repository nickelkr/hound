#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include <unistd.h>

struct options {
    char *interface;
};

typedef char err[PCAP_ERRBUF_SIZE];
typedef struct options options_t;

void setOpts(options_t *opts, int argc, char **argv) {
    int c;
    opts->interface = NULL;

    while((c = getopt(argc, argv, "d:")) != -1) {
        switch (c) {
            case 'd':
                opts->interface = optarg;
                break;
            case '?':
                if (optopt == 'd')
                    fprintf(stderr, "Options -%c requires a argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Uknown options -%c.\n", optopt);
                else
                    fprintf(stderr, "Uknown option (non-printable character).\n");
                exit(1);
            default:
                break;
        }
    }
}

void notify(char *err) {
    fprintf(stderr, "Error: %s", err);
    exit(1);
}

pcap_t* create(char *device) {
    err err = "";
    pcap_t *interface;

    if (device == NULL)
        device = pcap_lookupdev(err);
    if (device == NULL)
        notify(err);

    interface = pcap_create(device, err);
    if (interface == NULL)
        notify(err);

    return interface;
}


int main(int argc, char **argv) {
    options_t *opts = {NULL};
    pcap_t *interface;

    setOpts(opts, argc, argv);
    interface = create(opts->interface);


    return 0;
}

