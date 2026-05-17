#ifndef RUSTOS_STRING_H
#define RUSTOS_STRING_H

#include <stddef.h>

void* memcpy(void* restrict dst, const void* restrict src, size_t n);
void* memmove(void* dst, const void* src, size_t n);
void* memset(void* dst, int c, size_t n);
int memcmp(const void* lhs, const void* rhs, size_t n);
size_t strlen(const char* s);
size_t strnlen(const char* s, size_t max_len);
int strcmp(const char* lhs, const char* rhs);
int strncmp(const char* lhs, const char* rhs, size_t n);
char* strstr(const char* haystack, const char* needle);

#endif
