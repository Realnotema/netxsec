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

typedef struct {
    char *interface;
    char *dest_ip;
    int port;
    uint8_t flags;
} send_args_tcp_t;

typedef struct {
    const char *interface;
    const char *source_ip;
} send_args_icmp_t;

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
    char *inter = send_args->interface;
    char *destip = send_args->dest_ip;
    int port = send_args->port;
    uint8_t flags = send_args->flags;

    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    libnet_t *lc = libnet_init(LIBNET_RAW4, inter, errbuf_libnet);
    u_int32_t ip_addr = libnet_name2addr4(lc, destip, LIBNET_DONT_RESOLVE);
    lc = kernelBuildTCP(lc, port, flags, ip_addr, errbuf_libnet);
    int written = libnet_write(lc);

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
    u_int32_t ip_addr = libnet_name2addr4(lc, destip, LIBNET_DONT_RESOLVE);
    lc = kernelBuildICMP(lc, ip_addr, errbuf_libnet);
    int written = libnet_write(lc);

    libnet_destroy(lc);
}

int main() {
    send_args_tcp_t send_args;
    send_args.interface = "en0";
    send_args.dest_ip = "45.33.32.156";
    send_args.flags = TH_SYN;
    send_args.port = 22;

    kernelSendICMP((void*)&send_args);
    
    return 0;
}
