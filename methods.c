#include <stdio.h>
#include <pthread.h>
#include "kernel.h"
#include "methods.h"

void hello() {
    printf("\n╔╗─╔╦═══╦════╦══╗╔══╦══╦═══╦══╗\n"
            "║╚═╝║╔══╩═╗╔═╩═╗║║╔═╣╔═╣╔══╣╔═╝\n"
            "║╔╗─║╚══╗─║║───║╚╝║─║╚═╣╚══╣║\n"
            "║║╚╗║╔══╝─║║───║╔╗║─╚═╗║╔══╣║\n"
            "║║─║║╚══╗─║║─╔═╝║║╚═╦═╝║╚══╣╚═╗\n"
            "╚╝─╚╩═══╝─╚╝─╚══╝╚══╩══╩═══╩══╝\n"
            "by realnotema\n\n"
    );

}

int isHostUp (void *argsSend, void *argsRead) {
    send_args_tcp_t *send_args = (send_args_tcp_t *) argsSend;
    read_args_t *read_args = (read_args_t *) argsRead;

    if (send_args == NULL || read_args == NULL) {
        fprintf(stderr, "Error: NULL arguments provided to scanTCPSYNOnePort\n");
        return 1;
    }

    printf("Target IP: %s\n", send_args->dest_ip);

    pthread_t read_thread;
    pthread_t send_thread;

    pthread_create(&read_thread, NULL, kernelRead, (void *)read_args);
    pthread_create(&send_thread, NULL, kernelSendICMP, (void *)send_args);

    pthread_join(send_thread, NULL);
    pthread_join(read_thread, NULL);

    return host_up;
}

void printPortSummary (DynamicPortArray *port_array) {
    while (port_array->size) {
        int port = pop_port(port_array);
        port_info_t info = kernelPortsPrint(port);
        printf("Open port: %d\nService: %s(%s)\n\n", info.port, info.service_name, info.proto);
        return;
    }
    printf("Port seems down.\n\n");
}

void scanTCPSYNOnePort(void *argsSend, void *argsRead) {
    send_args_tcp_t *send_args = (send_args_tcp_t *) argsSend;
    read_args_t *read_args = (read_args_t *) argsRead;

    if (send_args == NULL || read_args == NULL) {
        fprintf(stderr, "Error: NULL arguments provided to scanTCPSYNOnePort\n");
        return;
    }

    pthread_t read_thread;
    pthread_t send_thread;

    pthread_create(&read_thread, NULL, kernelRead, (void *)read_args);
    pthread_create(&send_thread, NULL, kernelSendTCP, (void *)send_args);

    pthread_join(send_thread, NULL);
    pthread_join(read_thread, NULL);

    printPortSummary(read_args->port_array);
}

void scanTCPSYNDSysPorts (void *argsSend, void *argsRead) {
    send_args_tcp_t *send_args = (send_args_tcp_t *) argsSend;
    read_args_t *read_args = (read_args_t *) argsRead;

    pthread_t read_thread;
    pthread_create(&read_thread, NULL, kernelRead, (void *)read_args);

    for (int i = 1; i < 1025; i++) {
        pthread_t send_thread;
        send_args->port = i;
        pthread_create(&send_thread, NULL, kernelSendTCP, (void *)send_args);
        pthread_join(send_thread, NULL);
    }

    pthread_join(read_thread, NULL);

    printPortSummary(read_args->port_array);
}

// Del. soon
int main() {
    srand(time(NULL));
    DynamicPortArray port_array;
    init_port_array(&port_array, 10);

    send_args_tcp_t send_args;
    send_args.interface = "en0";
    send_args.dest_ip = "scanme.nmap.org";
    send_args.flags = 0x02;
    send_args.port = 22;

    read_args_t read_args;
    read_args.interface = "en0";
    read_args.proto = "tcp";
    read_args.source_ip = "scanme.nmap.org";
    read_args.port = 22;
    read_args.port_array = &port_array;

    hello();
    // if (isHostUp(&send_args, &read_args) == 1) {
    //     printf("Host seems up.\n");
    // } else {
    //     printf("Host seems down. QUITTING!\n");
    //     return 1;
    // }
    // scanTCPSYNOnePort(&send_args, &read_args);

    free_port_array(&port_array);

    return 0;
}