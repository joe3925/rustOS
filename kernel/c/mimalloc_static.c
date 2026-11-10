#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#ifndef NDEBUG
#define NDEBUG 1
#endif

#ifndef MI_DEBUG
#define MI_DEBUG 0
#endif

#ifndef MI_SECURE
#define MI_SECURE 0
#endif

#ifndef MI_STAT
#define MI_STAT 0
#endif

#define MI_NO_ALIGNED_HINT 1

#include "mimalloc.h"

static inline void** rustos_thread_slots(void) {
  void** tls;
#if defined(__x86_64__)
  __asm__("movq %%gs:0x58, %0" : "=r"(tls));
#elif defined(__aarch64__)
  __asm__("ldr %0, [x18, #0x58]" : "=r"(tls));
#else
  #error "Unsupported rustOS TLS architecture"
#endif
  return tls;
}

#define MI_PRIM_THREAD_ID() ((uintptr_t)rustos_thread_slots())
#define MI_HAS_TLS_SLOT 2
#define MI_TLS_SLOT 1
static inline void* mi_prim_tls_slot(size_t slot) {
  (void)slot;
  void* heap;
#if defined(__x86_64__)
  __asm__ volatile("movq %%gs:0x10, %0" : "=r"(heap) : : "memory");
#elif defined(__aarch64__)
  __asm__ volatile("ldr %0, [x18, #0x10]" : "=r"(heap) : : "memory");
#endif
  return heap;
}

static inline void mi_prim_tls_slot_set(size_t slot, void* heap) {
  rustos_thread_slots()[slot] = heap;
#if defined(__x86_64__)
  __asm__ volatile("movq %0, %%gs:0x10" : : "r"(heap) : "memory");
#elif defined(__aarch64__)
  __asm__ volatile("str %0, [x18, #0x10]" : : "r"(heap) : "memory");
#endif
}

#include "mimalloc/internal.h"

static uint8_t rustos_small_bins[1 + MI_SMALL_OBJ_SIZE_MAX / sizeof(uintptr_t)];
#define MI_SMALL_BIN(words) (rustos_small_bins[words])
#define MI_SMALL_PAGE_QUEUE(heap, size) (&(heap)->pages[MI_SMALL_BIN(_mi_wsize_from_size(size))])

#include "alloc.c"
#include "alloc-aligned.c"
#include "arena.c"
#include "bitmap.c"
#include "heap.c"
#include "init.c"
#include "libc.c"
#include "options.c"
#include "os.c"
#include "page.c"
#include "random.c"
#include "segment.c"
#include "segment-map.c"
#include "stats.c"

size_t rustos_mi_configure_options(void) {
  for (size_t words = 0; words < sizeof(rustos_small_bins); words++) {
    rustos_small_bins[words] = (uint8_t)_mi_bin(words * sizeof(uintptr_t));
  }
  mi_option_set(mi_option_eager_commit_delay, 1);
  return MI_SEGMENT_SIZE;
}
