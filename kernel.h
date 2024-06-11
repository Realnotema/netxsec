#ifndef KERNEL_H
#define KERNEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

typedef struct {
    char *interface;
    char *dest_ip;
    int port;
    uint8_t flags;
} send_args_tcp_t;

typedef struct {
    char *interface;
    char *source_ip;
} send_args_icmp_t;

typedef struct {
    int port;
    char *service_name;
    char *proto;
} port_info_t;

typedef struct {
    const char *interface;
    int port;
    const char *source_ip;
    char *proto;
    uint8_t flags; 
} read_args_t;

static char errbuf_libnet[LIBNET_ERRBUF_SIZE];
static char errbuf_pcap[PCAP_ERRBUF_SIZE];
static libnet_t *lc = NULL;

libnet_t *kernelBuildTCP(libnet_t *lc, int port, uint8_t flags, u_int32_t ipaddr, char errbuf_libnet[]);

void *kernelSendTCP(void *args);

libnet_t *kernelBuildICMP(libnet_t *lc, u_int32_t ipaddr, char errbuf_libnet[]);

void kernelSendICMP(void *args);

port_info_t kernelPortsPrint(int port);

void *kernelRead(void *args);

#endif /* KERNEL_H */
