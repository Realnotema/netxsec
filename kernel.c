/*
FOR REFERENCE ONLY

There you can see kernel realisation of TCP SYN, TCP FIN, TCP ACK,
TCP CONNECT, UDP & ICMP methods.

DO NOT USE THIS CODE IF YOU DO NOT KNOW THE BASICS OF NETWORKING 
AND DO NOT HAVE PERMISSION TO SCAN THE NETWORK (HOST)

Code by Realnotema
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include "kernel.h"

libnet_t *kernelBuildTCP(libnet_t *lc, int port, uint8_t flags, u_int32_t ipaddr, char errbuf_libnet[]) {
    libnet_ptag_t tcp_tag = libnet_build_tcp(
            22,
            port,
            0,
            0,
            flags,
            1024,
            0,
            0,
            LIBNET_TCP_H,
            NULL,
            0,
            lc,
            0
        );
    int ret_ipv4 = libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPPROTO_TCP, ipaddr, lc);
    return lc;
}

void kernelSendTCP(void *args) {
    send_args_tcp_t *send_args = (send_args_tcp_t *)args;
    if (send_args == NULL || send_args->interface == NULL || send_args->dest_ip == NULL) {
        fprintf(stderr, "Error: Invalid send arguments\n");
        return;
    }

    char *inter = send_args->interface;
    char *destip = send_args->dest_ip;
    int port = send_args->port;
    uint8_t flags = send_args->flags;

    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    libnet_t *lc = libnet_init(LIBNET_RAW4, inter, errbuf_libnet);
    if (lc == NULL) {
        fprintf(stderr, "Error: Failed to initialize libnet - %s\n", errbuf_libnet);
        return;
    }

    u_int32_t ip_addr = libnet_name2addr4(lc, destip, LIBNET_RESOLVE);
    if (ip_addr == -1) {
        fprintf(stderr, "Error: Failed to resolve destination IP address\n");
        libnet_destroy(lc);
        return;
    }

    lc = kernelBuildTCP(lc, port, flags, ip_addr, errbuf_libnet);
    if (lc == NULL) {
        fprintf(stderr, "Error: Failed to build TCP packet - %s\n", errbuf_libnet);
        libnet_destroy(lc);
        return;
    }

    int written = libnet_write(lc);
    if (written == -1) {
        fprintf(stderr, "Error: Failed to send TCP packet - %s\n", libnet_geterror(lc));
    } else {
        printf("Successfully sent TCP packet to %s:%d\n", destip, port);
    }

    libnet_destroy(lc);
}


libnet_t *kernelBuildICMP(libnet_t *lc, u_int32_t ipaddr, char errbuf_libnet[]) {
    libnet_ptag_t icmp_tag = libnet_build_icmpv4_echo(
        ICMP_ECHO,
        0, 
        0,    
        12345,  
        1,
        NULL,
        0,
        lc,
        0
    );
    int ret_ipv4 = libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, IPPROTO_ICMP, ipaddr, lc);
    return lc;
}

void kernelSendICMP(void *args) {
    send_args_tcp_t *send_args = (send_args_tcp_t *)args;
    char *inter = send_args->interface;
    char *destip = send_args->dest_ip;
    int port = send_args->port;
    uint8_t flags = send_args->flags;

    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    libnet_t *lc = libnet_init(LIBNET_RAW4, inter, errbuf_libnet);
    u_int32_t ip_addr = libnet_name2addr4(lc, destip, LIBNET_RESOLVE);
    lc = kernelBuildICMP(lc, ip_addr, errbuf_libnet);
    int written = libnet_write(lc);

    libnet_destroy(lc);
}

// Nowadays Unix-only
port_info_t kernelPortsPrint (int port) {
    port_info_t info;
    info.port = -1;
    FILE *file = fopen("/etc/services", "r");
    if (file == NULL)
        return info;

    char line[256];
    char service_name[64];
    int service_port;
    char proto[16];

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#') {
            continue;
        }

        if (sscanf(line, "%63s %d/%15s", service_name, &service_port, proto) == 3) {
            if (service_port == port) {
                info.port = port;
                info.service_name = service_name;
                info.proto = proto;
                fclose(file);
                return info;
            }
        }
    }

    fclose(file);
    return info;
}

void kernelRead(void *args) {
    read_args_t *info = (read_args_t *)args;
    if (info == NULL || info->interface == NULL) {
        fprintf(stderr, "Error: Invalid read arguments\n");
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    char filter_exp[100];
    sprintf(filter_exp, "host %s and port %d", info->source_ip, info->port);

    pcap_lookupnet(info->interface, &net, &mask, errbuf);
    pcap_t *handle = pcap_open_live(info->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Failed to open device - %s\n", errbuf);
        return;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error: Failed to compile filter expression\n");
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Failed to set filter\n");
        pcap_close(handle);
        return;
    }

    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            printf("Open port: %d\n", info->port);
        }
    }

    pcap_close(handle);
}

