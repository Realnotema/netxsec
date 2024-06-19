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
#include <netinet/ip_icmp.h> 
#include <pthread.h>
#include "kernel.h"

int host_up = 0;
int count_ports = 0;

void init_port_array(DynamicPortArray *arr, int initial_capacity) {
    arr->ports = (int *)malloc(initial_capacity * sizeof(int));
    arr->size = 0;
    arr->capacity = initial_capacity;
    arr->front = 0;
    arr->rear = -1;
}

void push_port(DynamicPortArray *arr, int port) {
    if (arr->size == arr->capacity) {
        arr->capacity *= 2;
        arr->ports = (int *)realloc(arr->ports, arr->capacity * sizeof(int));
    }
    arr->rear = (arr->rear + 1) % arr->capacity;
    arr->ports[arr->rear] = port;
    arr->size++;
}

int pop_port(DynamicPortArray *arr) {
    if (arr->size == 0) {
        fprintf(stderr, "Error: No ports to pop\n");
        return -1;
    }
    int port = arr->ports[arr->front];
    arr->front = (arr->front + 1) % arr->capacity;
    arr->size--;
    return port;
}

void free_port_array(DynamicPortArray *arr) {
    free(arr->ports);
    arr->ports = NULL;
    arr->size = 0;
    arr->capacity = 0;
    arr->front = 0;
    arr->rear = -1;
}

libnet_t *kernelBuildTCP(libnet_t *lc, int port, uint8_t flags, u_int32_t ipaddr, char errbuf_libnet[]) {
    libnet_ptag_t tcp_tag = libnet_build_tcp(
            51100,
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

void *kernelSendTCP(void *args) {
    send_args_tcp_t *send_args = (send_args_tcp_t *)args;
    if (send_args == NULL || send_args->interface == NULL || send_args->dest_ip == NULL) {
        fprintf(stderr, "Error: Invalid send arguments\n");
        return NULL;
    }

    char *inter = send_args->interface;
    char *destip = send_args->dest_ip;
    int port = send_args->port;
    uint8_t flags = send_args->flags;

    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    libnet_t *lc = libnet_init(LIBNET_RAW4, inter, errbuf_libnet);
    if (lc == NULL) {
        fprintf(stderr, "Error: Failed to initialize libnet - %s\n", errbuf_libnet);
        return NULL;
    }

    u_int32_t ip_addr = libnet_name2addr4(lc, destip, LIBNET_RESOLVE);
    if (ip_addr == -1) {
        fprintf(stderr, "Error: Failed to resolve destination IP address\n");
        libnet_destroy(lc);
        return NULL;
    }

    lc = kernelBuildTCP(lc, port, flags, ip_addr, errbuf_libnet);
    if (lc == NULL) {
        fprintf(stderr, "Error: Failed to build TCP packet - %s\n", errbuf_libnet);
        libnet_destroy(lc);
        return NULL;
    }

    int written = libnet_write(lc);
    if (written == -1) {
        fprintf(stderr, "Error: Failed to send TCP packet - %s\n", libnet_geterror(lc));
    } 



    libnet_destroy(lc);
    return NULL;
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

void *kernelSendICMP(void *args) {
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
    return NULL;
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

void *kernelRead(void *args) {
    read_args_t *info = (read_args_t *)args;
    if (info == NULL || info->interface == NULL) {
        fprintf(stderr, "Error: Invalid read arguments\n");
        pthread_exit(NULL);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    char filter_exp[100];
    sprintf(filter_exp, "src host %s", info->source_ip);

    if (pcap_lookupnet(info->interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error: Failed to get network address and mask - %s\n", errbuf);
        pthread_exit(NULL);
    }

    pcap_t *handle = pcap_open_live(info->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Failed to open device - %s\n", errbuf);
        pthread_exit(NULL);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error: Failed to compile filter expression - %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Failed to set filter - %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *eth_hdr = (struct ether_header *)packet;
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);

            if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                printf("опаньки\n");
                push_port(info->port_array, ntohs(tcp_hdr->th_sport));
            }
        }
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            struct icmp *icmp_hdr = (struct icmp *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
        
            if (icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
                //printf("Received ICMP ECHO REPLY from: %s\n", inet_ntoa(ip_hdr->ip_src));
                host_up = 1;
            }
        }
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

