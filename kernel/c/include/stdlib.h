#ifndef RUSTOS_STDLIB_H
#define RUSTOS_STDLIB_H

#include <stddef.h>

#define NULL ((void*)0)

void abort(void) __attribute__((noreturn));
long strtol(const char* nptr, char** endptr, int base);
char* getenv(const char* name);

#endif
