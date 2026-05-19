#ifndef RUSTOS_WCHAR_H
#define RUSTOS_WCHAR_H

#include <stddef.h>

#ifndef __cplusplus
typedef int wchar_t;
#endif

size_t wcslen(const wchar_t* s);

#endif
