#ifndef RUSTOS_STDLIB_H
#define RUSTOS_STDLIB_H

#include <stddef.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

_Noreturn void abort(void);
long strtol(const char* nptr, char** endptr, int base);
char* getenv(const char* name);

#endif
