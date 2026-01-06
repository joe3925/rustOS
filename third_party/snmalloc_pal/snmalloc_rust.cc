#include "pal.h"

#define SNMALLOC_MEMORY_PROVIDER PALRust
#define SNMALLOC_PROVIDE_OWN_CONFIG

#include "snmalloc/snmalloc_core.h"
#include "snmalloc/backend/fixedglobalconfig.h"

namespace snmalloc
{
    // Use FixedRangeConfig with bounded pagemap - this avoids the massive
    // pagemap required for the full 48-bit address space and prevents
    // overflow when using kernel higher-half addresses
    using Config = FixedRangeConfig<PALRust>;
    using Alloc = Allocator<Config>;
}

#include "snmalloc/snmalloc_front.h"

#include <string.h>

using namespace snmalloc;

// Initialization state
static bool is_initialized = false;

// Initialize snmalloc with a bounded heap region
// Must be called before any allocations
// base: start of the heap region
// length: size of the heap region in bytes
extern "C" void sn_rust_init(void* base, size_t length)
{
    if (is_initialized)
        return;
    Config::init(nullptr, base, length);
    is_initialized = true;
}

extern "C" void* sn_rust_alloc(size_t alignment, size_t size)
{
    return alloc(aligned_size(alignment, size));
}

extern "C" void* sn_rust_alloc_zeroed(size_t alignment, size_t size)
{
    return alloc<Zero>(aligned_size(alignment, size));
}

extern "C" void sn_rust_dealloc(void* ptr, size_t alignment, size_t size)
{
    dealloc(ptr, aligned_size(alignment, size));
}

extern "C" void* sn_rust_realloc(
    void* ptr, size_t alignment, size_t old_size, size_t new_size)
{
    size_t aligned_old_size = aligned_size(alignment, old_size),
           aligned_new_size = aligned_size(alignment, new_size);
    if (
        size_to_sizeclass_full(aligned_old_size).raw() ==
        size_to_sizeclass_full(aligned_new_size).raw())
        return ptr;
    void* p = alloc(aligned_new_size);
    if (p)
    {
        memcpy(p, ptr, old_size < new_size ? old_size : new_size);
        dealloc(ptr, aligned_old_size);
    }
    return p;
}

extern "C" void sn_rust_statistics(
    size_t* current_memory_usage, size_t* peak_memory_usage)
{
    *current_memory_usage = Alloc::Config::Backend::get_current_usage();
    *peak_memory_usage = Alloc::Config::Backend::get_peak_usage();
}

extern "C" size_t sn_rust_usable_size(const void* ptr)
{
    return alloc_size(ptr);
}
