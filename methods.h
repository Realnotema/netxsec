#ifndef METHODS_H
#define METHODS_H

#include <stdio.h>
#include <pthread.h>
#include "kernel.h"

int isHostUp (void *argsSend, void *argsRead);

void printPortSummary (DynamicPortArray *port_array);

void scanTCPSYNOnePort(void *argsSend, void *argsRead);

void scanTCPSYNDSysPorts (void *argsSend, void *argsRead);

#endif /* METHODS_H */