#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include "../methods.h"
#include "../kernel.h"

void test_icmp_echo() {
    DynamicPortArray port_array;
    init_port_array(&port_array, 10);
    
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

    CU_ASSERT_EQUAL(isHostUp(&send_args, &read_args), 1);
    CU_ASSERT_EQUAL(isHostUp(NULL, &read_args), -1);
    send_args.dest_ip = "22.2.2.2";
    read_args.source_ip = "22.2.2.2";
    host_up = 0;
    CU_ASSERT_EQUAL(isHostUp(&send_args, &read_args), 0);
}

void test_tcp_syn_scan() {
    DynamicPortArray port_array;
    init_port_array(&port_array, 10);
    
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

    scanTCPSYNDSysPorts(&send_args, &read_args);
    CU_ASSERT_EQUAL(count_ports, 1);
    send_args.dest_ip = "22.2.2.2";
    read_args.source_ip = "22.2.2.2";
    count_ports = 0;
    scanTCPSYNDSysPorts(&send_args, &read_args);
    CU_ASSERT_EQUAL(count_ports, 0);
    count_ports = 0;
    scanTCPSYNDSysPorts(NULL, &read_args);
    CU_ASSERT_EQUAL(count_ports, -1);
}

int main() {
    CU_initialize_registry();

    CU_pSuite suite1 = CU_add_suite("Send ICMP echo suite", 0, 0);
    CU_add_test(suite1, "test of test_icmp_echo()", test_icmp_echo);
    CU_pSuite suite2 = CU_add_suite("Send TCP SYN suite", 0, 0);
    CU_add_test(suite2, "test of test_tcp_syn_scan()", test_tcp_syn_scan);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}