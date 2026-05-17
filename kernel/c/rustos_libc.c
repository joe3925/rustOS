#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

int errno;

void* memcpy(void* restrict dst, const void* restrict src, size_t n) {
  unsigned char* d = (unsigned char*)dst;
  const unsigned char* s = (const unsigned char*)src;
  for (size_t i = 0; i < n; i++) {
    d[i] = s[i];
  }
  return dst;
}

void* memmove(void* dst, const void* src, size_t n) {
  unsigned char* d = (unsigned char*)dst;
  const unsigned char* s = (const unsigned char*)src;
  if (d == s || n == 0) return dst;
  if (d < s) {
    for (size_t i = 0; i < n; i++) {
      d[i] = s[i];
    }
  }
  else {
    for (size_t i = n; i != 0; i--) {
      d[i - 1] = s[i - 1];
    }
  }
  return dst;
}

void* memset(void* dst, int c, size_t n) {
  unsigned char* d = (unsigned char*)dst;
  for (size_t i = 0; i < n; i++) {
    d[i] = (unsigned char)c;
  }
  return dst;
}

int memcmp(const void* lhs, const void* rhs, size_t n) {
  const unsigned char* a = (const unsigned char*)lhs;
  const unsigned char* b = (const unsigned char*)rhs;
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i]) return (a[i] < b[i] ? -1 : 1);
  }
  return 0;
}

size_t strlen(const char* s) {
  size_t n = 0;
  while (s != NULL && s[n] != 0) {
    n++;
  }
  return n;
}

size_t strnlen(const char* s, size_t max_len) {
  size_t n = 0;
  while (s != NULL && n < max_len && s[n] != 0) {
    n++;
  }
  return n;
}

int strcmp(const char* lhs, const char* rhs) {
  while (*lhs != 0 && *lhs == *rhs) {
    lhs++;
    rhs++;
  }
  return (int)(unsigned char)*lhs - (int)(unsigned char)*rhs;
}

int strncmp(const char* lhs, const char* rhs, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char a = (unsigned char)lhs[i];
    unsigned char b = (unsigned char)rhs[i];
    if (a != b || a == 0) return (int)a - (int)b;
  }
  return 0;
}

char* strstr(const char* haystack, const char* needle) {
  if (needle == NULL || needle[0] == 0) return (char*)haystack;
  if (haystack == NULL) return NULL;
  const size_t needle_len = strlen(needle);
  for (const char* h = haystack; *h != 0; h++) {
    if (strncmp(h, needle, needle_len) == 0) {
      return (char*)h;
    }
  }
  return NULL;
}

size_t wcslen(const wchar_t* s) {
  size_t n = 0;
  while (s != NULL && s[n] != 0) {
    n++;
  }
  return n;
}

long strtol(const char* nptr, char** endptr, int base) {
  if (endptr != NULL) *endptr = (char*)nptr;
  if (nptr == NULL) return 0;
  if (base != 0 && base != 10) return 0;

  const char* p = nptr;
  int sign = 1;
  if (*p == '-') {
    sign = -1;
    p++;
  }
  else if (*p == '+') {
    p++;
  }

  long value = 0;
  while (*p >= '0' && *p <= '9') {
    value = value * 10 + (*p - '0');
    p++;
  }
  if (endptr != NULL) *endptr = (char*)p;
  return value * sign;
}

char* getenv(const char* name) {
  (void)name;
  return NULL;
}

long pathconf(const char* path, int name) {
  (void)path;
  (void)name;
  return -1;
}

char* realpath(const char* restrict path, char* restrict resolved_path) {
  (void)path;
  (void)resolved_path;
  errno = ENOTSUP;
  return NULL;
}

void abort(void) {
  __builtin_trap();
  for (;;) {}
}

int pthread_mutex_trylock(pthread_mutex_t* mutex) {
  uintptr_t expected = 0;
  return atomic_compare_exchange_strong_explicit(&mutex->state, &expected, 1, memory_order_acquire, memory_order_relaxed) ? 0 : EAGAIN;
}

int pthread_mutex_lock(pthread_mutex_t* mutex) {
  while (pthread_mutex_trylock(mutex) != 0) {
    __asm__ volatile("pause" ::: "memory");
  }
  return 0;
}

int pthread_mutex_unlock(pthread_mutex_t* mutex) {
  atomic_store_explicit(&mutex->state, 0, memory_order_release);
  return 0;
}

int pthread_mutex_destroy(pthread_mutex_t* mutex) {
  (void)mutex;
  return 0;
}
