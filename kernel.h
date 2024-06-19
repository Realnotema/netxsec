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
    int *ports;
    int size;
    int capacity;
    int front;
    int rear;
} DynamicPortArray;

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
    char *source_ip;
    char *proto;
    uint8_t flags;
    DynamicPortArray *port_array;
} read_args_t;

static char errbuf_libnet[LIBNET_ERRBUF_SIZE];
static char errbuf_pcap[PCAP_ERRBUF_SIZE];
extern int host_up;
extern int count_ports;

libnet_t *kernelBuildTCP(libnet_t *lc, int port, uint8_t flags, u_int32_t ipaddr, char errbuf_libnet[]);

void *kernelSendTCP(void *args);

libnet_t *kernelBuildICMP(libnet_t *lc, u_int32_t ipaddr, char errbuf_libnet[]);

void *kernelSendICMP(void *args);

port_info_t kernelPortsPrint(int port);

void *kernelRead(void *args);

void free_port_array(DynamicPortArray *arr);

int pop_port(DynamicPortArray *arr);

void push_port(DynamicPortArray *arr, int port);

void init_port_array(DynamicPortArray *arr, int initial_capacity);

#endif /* KERNEL_H */