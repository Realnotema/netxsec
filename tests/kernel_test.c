#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include "../kernel.h"

void test_init_port_array() {
    DynamicPortArray arr;
    init_port_array(&arr, 5);
    CU_ASSERT_PTR_NOT_NULL(arr.ports);
    CU_ASSERT_EQUAL(arr.size, 0);
    CU_ASSERT_EQUAL(arr.capacity, 5);
    CU_ASSERT_EQUAL(arr.front, 0);
    CU_ASSERT_EQUAL(arr.rear, -1);
    free_port_array(&arr);
}

void test_push_port() {
    DynamicPortArray arr;
    init_port_array(&arr, 2);

    push_port(&arr, 80);
    CU_ASSERT_EQUAL(arr.size, 1);
    CU_ASSERT_EQUAL(arr.ports[arr.rear], 80);

    push_port(&arr, 443);
    CU_ASSERT_EQUAL(arr.size, 2);
    CU_ASSERT_EQUAL(arr.ports[arr.rear], 443);

    push_port(&arr, 8080);
    CU_ASSERT_EQUAL(arr.size, 3);
    CU_ASSERT_EQUAL(arr.capacity, 4);
    CU_ASSERT_EQUAL(arr.ports[arr.rear], 8080);

    free_port_array(&arr);
}

void test_pop_port() {
    DynamicPortArray arr;
    init_port_array(&arr, 2);

    push_port(&arr, 80);
    push_port(&arr, 443);

    int port = pop_port(&arr);
    CU_ASSERT_EQUAL(port, 80);
    CU_ASSERT_EQUAL(arr.size, 1);

    port = pop_port(&arr);
    CU_ASSERT_EQUAL(port, 443);
    CU_ASSERT_EQUAL(arr.size, 0);

    port = pop_port(&arr);
    CU_ASSERT_EQUAL(port, -1);

    free_port_array(&arr);
}

void test_kernelPortsPrint() {
    port_info_t info = kernelPortsPrint(80);
    CU_ASSERT_EQUAL(info.port, 80);

    info = kernelPortsPrint(123456);
    CU_ASSERT_EQUAL(info.port, -1);
}

int main() {
    CU_initialize_registry();

    CU_pSuite suite1 = CU_add_suite("DynamicPortArray Suite", 0, 0);
    CU_add_test(suite1, "test of init_port_array()", test_init_port_array);
    CU_add_test(suite1, "test of push_port()", test_push_port);
    CU_add_test(suite1, "test of pop_port()", test_pop_port);

    CU_pSuite suite2 = CU_add_suite("kernelPortsPrint Suite", 0, 0);
    CU_add_test(suite2, "test of kernelPortsPrint()", test_kernelPortsPrint);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
