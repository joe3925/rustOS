/*
 * Freestanding mimalloc primitive layer for rustOS.
 *
 * The Rust side owns virtual range allocation and exposes a small, allocation
 * free ABI to this C layer. Mimalloc sees memory as always committed because
 * the kernel heap is mapped before mimalloc is enabled.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mimalloc.h"
#include "mimalloc/prim.h"

#define RUSTOS_ENOMEM 12
#define RUSTOS_PAGE_SIZE ((size_t)4096)

extern void* rustos_mi_os_alloc(size_t size, size_t alignment);
extern void rustos_mi_os_free(void* addr, size_t size);
extern bool rustos_mi_os_commit(void* addr, size_t size);
extern size_t rustos_mi_physical_memory_kib(void);
extern uint64_t rustos_mi_clock_now(void);
extern bool rustos_mi_random_buf(void* buf, size_t len);
extern void rustos_mi_out_stderr(const char* msg);
extern void rustos_mi_thread_yield(void);

bool rustos_mi_manage_arena(void* start, size_t size) {
  return mi_manage_os_memory(start, size, false, false, false, -1);
}

static size_t rustos_max_size(size_t a, size_t b) {
  return (a > b ? a : b);
}

void _mi_prim_mem_init(mi_os_mem_config_t* config) {
  if (config == NULL) return;
  config->page_size = RUSTOS_PAGE_SIZE;
  config->large_page_size = 0;
  config->alloc_granularity = RUSTOS_PAGE_SIZE;
  config->physical_memory_in_kib = rustos_mi_physical_memory_kib();
  config->virtual_address_bits = 48;
  config->has_overcommit = false;
  config->has_partial_free = false;
  config->has_virtual_reserve = false;
}

int _mi_prim_alloc(void* hint_addr, size_t size, size_t try_alignment, bool commit, bool allow_large, bool* is_large, bool* is_zero, void** addr) {
  (void)hint_addr;
  (void)commit;
  (void)allow_large;

  if (is_large != NULL) *is_large = false;
  if (is_zero != NULL) *is_zero = true;
  if (addr == NULL) return RUSTOS_ENOMEM;

  const size_t alignment = rustos_max_size(try_alignment, RUSTOS_PAGE_SIZE);
  void* p = rustos_mi_os_alloc(size, alignment);
  *addr = p;
  return (p == NULL ? RUSTOS_ENOMEM : 0);
}

int _mi_prim_free(void* addr, size_t size) {
  rustos_mi_os_free(addr, size);
  return 0;
}

int _mi_prim_commit(void* addr, size_t size, bool* is_zero) {
  if (!rustos_mi_os_commit(addr, size)) {
    return RUSTOS_ENOMEM;
  }
  if (is_zero != NULL) *is_zero = false;
  return 0;
}

int _mi_prim_decommit(void* addr, size_t size, bool* needs_recommit) {
  (void)addr;
  (void)size;
  if (needs_recommit != NULL) *needs_recommit = false;
  return 0;
}

int _mi_prim_reset(void* addr, size_t size) {
  (void)addr;
  (void)size;
  return 0;
}

int _mi_prim_reuse(void* addr, size_t size) {
  (void)addr;
  (void)size;
  return 0;
}

int _mi_prim_protect(void* addr, size_t size, bool protect) {
  (void)addr;
  (void)size;
  (void)protect;
  return 0;
}

int _mi_prim_alloc_huge_os_pages(void* hint_addr, size_t size, int numa_node, bool* is_zero, void** addr) {
  (void)hint_addr;
  (void)size;
  (void)numa_node;
  if (is_zero != NULL) *is_zero = false;
  if (addr != NULL) *addr = NULL;
  return RUSTOS_ENOMEM;
}

size_t _mi_prim_numa_node(void) {
  return 0;
}

size_t _mi_prim_numa_node_count(void) {
  return 1;
}

mi_msecs_t _mi_prim_clock_now(void) {
  return (mi_msecs_t)rustos_mi_clock_now();
}

void _mi_prim_process_info(mi_process_info_t* pinfo) {
  if (pinfo == NULL) return;
  pinfo->elapsed = rustos_mi_clock_now();
  pinfo->utime = 0;
  pinfo->stime = 0;
  pinfo->current_rss = 0;
  pinfo->peak_rss = 0;
  pinfo->current_commit = 0;
  pinfo->peak_commit = 0;
  pinfo->page_faults = 0;
}

void _mi_prim_out_stderr(const char* msg) {
  rustos_mi_out_stderr(msg);
}

bool _mi_prim_getenv(const char* name, char* result, size_t result_size) {
  (void)name;
  if (result != NULL && result_size != 0) {
    result[0] = 0;
  }
  return false;
}

bool _mi_prim_random_buf(void* buf, size_t buf_len) {
  return rustos_mi_random_buf(buf, buf_len);
}

void _mi_prim_thread_init_auto_done(void) {}

void _mi_prim_thread_done_auto_done(void) {}

void _mi_prim_thread_associate_default_heap(mi_heap_t* heap) {
  (void)heap;
}

void _mi_prim_thread_yield(void) {
  rustos_mi_thread_yield();
}

bool _mi_is_redirected(void) {
  return false;
}

bool _mi_allocator_init(const char** message) {
  if (message != NULL) *message = NULL;
  return true;
}

void _mi_allocator_done(void) {}
