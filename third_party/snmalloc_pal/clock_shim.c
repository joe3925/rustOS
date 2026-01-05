// Minimal clock_gettime shim for freestanding build.
#include <stdint.h>

// Provided by the kernel (see pal.h)
uint64_t krnl_snmalloc_time_ms(void);

#ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC 1
#endif

#ifndef _TIMESPEC_DEFINED
#  define _TIMESPEC_DEFINED
typedef long time_t;
struct timespec
{
  time_t tv_sec;
  long tv_nsec;
};
#endif

int clock_gettime(int clk, struct timespec* ts)
{
  (void)clk; // Only CLOCK_MONOTONIC is used
  uint64_t ms = krnl_snmalloc_time_ms();
  ts->tv_sec = (time_t)(ms / 1000);
  ts->tv_nsec = (long)((ms % 1000) * 1000000ULL);
  return 0;
}
