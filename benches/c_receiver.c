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
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, const char *argv[])
{
    if (argc != 2) {
        printf("usage: %s <interface>\n", argv[0]);
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

    char read_buffer[4096];
    unsigned int buflen = 4096;

    if (ioctl(fd, BIOCSBLEN, &buflen) == -1) {
        perror("ioctl");
        return 1;
    }

    struct ifreq iface;
    memset(&iface, 0, sizeof(iface));
    memcpy(iface.ifr_name, argv[1], strlen(argv[1]));

    if (ioctl(fd, BIOCSETIF, &iface) == -1) {
        perror("ioctl");
        return 1;
    }

    unsigned int one = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &one) == -1) {
        perror("ioctl");
        return 1;
    }

    if (ioctl(fd, BIOCSHDRCMPLT, &one) == -1) {
        perror("ioctl");
        return 1;
    }

    unsigned long timestamps[201];
    time_t orig_secs;
    size_t ts_idx = 0;
    ssize_t bytes_read;
    size_t i = 0, j = 0;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    orig_secs = tv.tv_sec;
    timestamps[ts_idx++] = tv.tv_usec;

    while ((bytes_read = read(fd, read_buffer, buflen)) != -1) {
        char *cursor = read_buffer;
        char *end = read_buffer + bytes_read;
        while (cursor < end) {
            struct bpf_hdr *header = (struct bpf_hdr*)cursor;
            i++;
            if (i == 1000000) {
                gettimeofday(&tv, NULL);
                timestamps[ts_idx++] = 1000000 * (tv.tv_sec - orig_secs) + tv.tv_usec;
                if (ts_idx == 201) {
                    goto print_results;
                }
                i = 0;
            }
            cursor += BPF_WORDALIGN(header->bh_hdrlen + header->bh_caplen);
        }
    }

    if (bytes_read == -1) {
        perror("read");
        return 1;
    }

print_results:
    for (i = 0, j = 1; j < 201; i++, j++) {
        printf("%lu\n", timestamps[j] - timestamps[i]);
    }

    return 0;
}
