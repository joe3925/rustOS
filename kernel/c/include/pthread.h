#ifndef RUSTOS_PTHREAD_H
#define RUSTOS_PTHREAD_H

#include <stdatomic.h>
#include <stdint.h>

typedef struct {
  _Atomic(uintptr_t) state;
} pthread_mutex_t;

#define PTHREAD_MUTEX_INITIALIZER { ATOMIC_VAR_INIT(0) }

int pthread_mutex_trylock(pthread_mutex_t* mutex);
int pthread_mutex_lock(pthread_mutex_t* mutex);
int pthread_mutex_unlock(pthread_mutex_t* mutex);
int pthread_mutex_destroy(pthread_mutex_t* mutex);

#endif
