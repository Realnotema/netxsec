#include <stdio.h>
#include <pthread.h>
#include "kernel.h"
#include "methods.h"
#include <time.h>

void hello() {
    printf("\n╔╗─╔╦═══╦════╦══╗╔══╦══╦═══╦══╗\n"
            "║╚═╝║╔══╩═╗╔═╩═╗║║╔═╣╔═╣╔══╣╔═╝\n"
            "║╔╗─║╚══╗─║║───║╚╝║─║╚═╣╚══╣║\n"
            "║║╚╗║╔══╝─║║───║╔╗║─╚═╗║╔══╣║\n"
            "║║─║║╚══╗─║║─╔═╝║║╚═╦═╝║╚══╣╚═╗\n"
            "╚╝─╚╩═══╝─╚╝─╚══╝╚══╩══╩═══╩══╝\n"
            "\n"
    );

}

int isHostUp (void *argsSend, void *argsRead) {
    send_args_tcp_t *send_args = (send_args_tcp_t *) argsSend;
    read_args_t *read_args = (read_args_t *) argsRead;

    if (send_args == NULL || read_args == NULL) {
        fprintf(stderr, "Error: NULL arguments provided to scanTCPSYNOnePort\n");
        return -1;
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

void scanTCPSYNDSysPorts(void *argsSend, void *argsRead) {
    if (argsSend == NULL || argsRead == NULL) {
        count_ports = -1;
        return;
    }

    send_args_tcp_t *send_args = (send_args_tcp_t *) argsSend;
    read_args_t *read_args = (read_args_t *) argsRead;

    pthread_t read_thread;
    pthread_create(&read_thread, NULL, kernelRead, (void *)read_args);

    const int num_ports_per_scan = 10000;  // Количество портов на одну итерацию сканирования
    const int total_ports = 60000;         // Общее количество портов для сканирования (6 * 10000)
    const int num_scans = total_ports / num_ports_per_scan;  // Количество итераций

    for (int scan = 0; scan < num_scans; scan++) {
        printf("Scanning ports from %d to %d\n", scan * num_ports_per_scan + 1, (scan + 1) * num_ports_per_scan);

        pthread_t send_threads[num_ports_per_scan];  // Массив потоков для отправки
        int thread_count = 0;

        for (int i = 0; i < num_ports_per_scan; i++) {
            send_args->port = scan * num_ports_per_scan + i + 1;
            // Создаем новый поток для отправки пакета на каждый порт
            pthread_create(&send_threads[thread_count], NULL, kernelSendTCP, (void *)send_args);
            thread_count++;
        }

        // Ждем завершения всех потоков отправки
        for (int i = 0; i < thread_count; i++) {
            pthread_join(send_threads[i], NULL);
        }

        // Увеличиваем время ожидания для получения ответов
        usleep(1000000);  // Ждем 500 миллисекунд

        printf("Completed scanning ports from %d to %d\n", scan * num_ports_per_scan + 1, (scan + 1) * num_ports_per_scan);
    }

    // Завершаем поток чтения
    pthread_join(read_thread, NULL);

    count_ports = read_args->port_array->size;
    printPortSummary(read_args->port_array);
}

void menu() {
    DynamicPortArray port_array;
    init_port_array(&port_array, 10);
    send_args_tcp_t send_args;
    read_args_t read_args;
    pcap_if_t *it;

    send_args.dest_ip = (char *) malloc(15*sizeof(char));
    pcap_findalldevs(&it, errbuf_pcap);
    printf("Interface (default %s): ", it->name);
    scanf("%s", send_args.interface);
    read_args.interface = send_args.interface;
    pcap_freealldevs(it);
    printf("IP (or domain name): ");
    scanf("%s", send_args.dest_ip);
    read_args.source_ip = send_args.dest_ip;
    printf("Port (or range): ");
    scanf("%d", &send_args.port);
    read_args.port = send_args.port;
    read_args.proto = "tcp";
    send_args.flags = 0x02;

    read_args.port_array = &port_array;
    system("clear");
    hello();
    printf("interfacex");
}
//Del. soon
int main() {
    srand(time(NULL));
    DynamicPortArray port_array;
    init_port_array(&port_array, 10);
    clock_t start, end;
    
    // Test with your args
    send_args_tcp_t send_args;
    send_args.interface = "bridge101";
    send_args.dest_ip = "172.16.4.168";
    send_args.flags = 0x02;

    // Test with your args
    read_args_t read_args;
    read_args.interface = "bridge101";
    read_args.proto = "tcp";
    read_args.source_ip = "172.16.4.168";
    read_args.port_array = &port_array;

    send_args.port = 22;
    read_args.port = 22;
    start = time(NULL);
    // scanTCPSYNOnePort(&send_args, &read_args);
    scanTCPSYNDSysPorts(&send_args, &read_args);
    end = time(NULL);
    printf("Done %.1f sec.\n", difftime(end, start));

    return 0;
}