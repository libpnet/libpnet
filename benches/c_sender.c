// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, const char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <interface> <destination>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[2]) != 17) {
        fprintf(stderr, "destination must be in the form aa:bb:cc:dd:ee:ff");
        return 1;
    }

    int fd;
    char path[20];
    for (int i = 0; i < 1000; i++) {
        snprintf(path, 20, "/dev/bpf%d", i);
        fd = open(path, O_RDWR, 0);
        if (fd != -1) {
            break;
        }
    }

    struct ifreq iface;
    memset(&iface, 0, sizeof(iface));
    memcpy(iface.ifr_name, argv[1], strlen(argv[1]));

    if (ioctl(fd, BIOCSETIF, &iface) == -1) {
        perror("ioctl");
        return 1;
    }

    char ether_dhost[6];
    for (int i = 0; i < 6; i++, argv[2] += 3) {
        ether_dhost[i] = strtol(argv[2], NULL, 16);
    }

    char buffer[64];

    memset(buffer, 0, sizeof(buffer));

    struct ether_header *eh = (struct ether_header *)&buffer;
    memcpy(eh->ether_dhost, ether_dhost, 6);
    /* source filled out automatically */
    eh->ether_type = htons(ETHERTYPE_IP);

    struct ip *ih = (struct ip *)&buffer + sizeof(struct ether_header);
    ih->ip_v = 4;
    ih->ip_hl = 5;
    ih->ip_len = htons(sizeof(struct ether_header) + sizeof(struct ip) + 5);
    ih->ip_ttl = 4;
    ih->ip_p = IPPROTO_UDP;
    ih->ip_src.s_addr = 127 << 24 | 0 << 16 | 0 << 8 | 1;
    ih->ip_dst.s_addr = 127 << 24 | 0 << 16 | 0 << 8 | 1;
    ih->ip_sum = 0; /* FIXME checksum */

    struct udphdr *uh = (struct udphdr *)&buffer + sizeof(struct ether_header) + sizeof(struct ip);
    uh->uh_sport = htons(1234);
    uh->uh_dport = htons(1234);
    uh->uh_ulen = sizeof(struct udphdr) + 5;
    uh->uh_sum = 0; /* FIXME checksum */

    memcpy(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr), "cmesg", 5);

    for (;;) {
        if (write(fd, buffer, 60) == -1) {
            break;
        }
    }

    perror("write");
    return 1;
}

