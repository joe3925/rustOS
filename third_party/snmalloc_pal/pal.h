#pragma once

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

// Stubs for functions snmalloc references but we don't use on x86_64 freestanding
// (the code paths using these are compile-time dead on x86_64, but still parsed)
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 0
#endif
inline int clock_gettime(int, struct timespec*) { return -1; }
[[noreturn]] inline void abort() { while(1); }

#include "snmalloc/aal/aal.h"
#include "snmalloc/ds_core/ds_core.h"
#include "snmalloc/pal/pal_concept.h"
#include "snmalloc/pal/pal_timer_default.h"
extern "C" void *memset(void *dst, int value, size_t n);
extern "C"
{
    void *krnl_snmalloc_reserve(size_t size);
    void *krnl_snmalloc_reserve_aligned(size_t size, size_t alignment);
    void krnl_snmalloc_release(void *base, size_t size);

    void krnl_snmalloc_decommit(void *base, size_t size);
    bool krnl_snmalloc_commit(void *base, size_t size, bool zero);

    void krnl_snmalloc_message_cstr(const char *str);
    [[noreturn]] void krnl_snmalloc_error_cstr(const char *str);

    uint64_t krnl_snmalloc_entropy64();
    uint64_t krnl_snmalloc_time_ms();

    void krnl_snmalloc_wait_on_u8(const void *addr, uint8_t expected);
    void krnl_snmalloc_wake_one_u8(const void *addr);
    void krnl_snmalloc_wake_all_u8(const void *addr);
}

namespace snmalloc
{
    struct PALRust : public PalTimerDefaultImpl<PALRust>
    {
        static SNMALLOC_CONSTINIT_STATIC size_t minimum_alloc_size = 0x10000;
        static constexpr size_t page_size = 0x1000;
        static constexpr size_t address_bits = Aal::address_bits;
        static constexpr uint64_t pal_features =
            AlignedAllocation | Entropy | Time | WaitOnAddress;

        static uint64_t internal_time_in_ms() noexcept
        {
            return krnl_snmalloc_time_ms();
        }

        static uint64_t get_entropy64() noexcept
        {
            return krnl_snmalloc_entropy64();
        }

        static void message(const char *const str) noexcept
        {
            krnl_snmalloc_message_cstr(str);
        }

        [[noreturn]] static void error(const char *const str) noexcept
        {
            krnl_snmalloc_error_cstr(str);
        }

        static void notify_not_using(void *p, size_t size) noexcept
        {
            SNMALLOC_ASSERT(is_aligned_block<page_size>(p, size));
            krnl_snmalloc_decommit(p, size);
        }

        template <ZeroMem zero_mem>
        static bool notify_using(void *p, size_t size) noexcept
        {
            if constexpr (zero_mem == YesZero)
                SNMALLOC_ASSERT(is_aligned_block<page_size>(p, size));
            return krnl_snmalloc_commit(p, size, zero_mem == YesZero);
        }

        static bool notify_using_readonly(void *, size_t) noexcept
        {
            return false;
        }

        template <bool page_aligned = false>
        static void zero(void *p, size_t size) noexcept
        {
            memset(p, 0, size);
        }

        static void *reserve(size_t size) noexcept
        {
            return krnl_snmalloc_reserve(size);
        }

        template <bool state_using = false>
        static void *reserve_aligned(size_t size) noexcept
        {
            void *p = krnl_snmalloc_reserve_aligned(size, size);
            if constexpr (state_using)
            {
                if (!krnl_snmalloc_commit(p, size, false))
                    return nullptr;
            }
            return p;
        }

        static void release(void *p, size_t size) noexcept
        {
            krnl_snmalloc_release(p, size);
        }

        using WaitingWord = uint8_t;

        template <typename T>
        static void wait_on_address(stl::Atomic<T> &addr, T expected) noexcept
        {
            static_assert(sizeof(T) == 1);
            while (addr.load(stl::memory_order_acquire) == expected)
                krnl_snmalloc_wait_on_u8(&addr, (uint8_t)expected);
        }

        template <typename T>
        static void notify_one_on_address(stl::Atomic<T> &addr) noexcept
        {
            static_assert(sizeof(T) == 1);
            krnl_snmalloc_wake_one_u8(&addr);
        }

        template <typename T>
        static void notify_all_on_address(stl::Atomic<T> &addr) noexcept
        {
            static_assert(sizeof(T) == 1);
            krnl_snmalloc_wake_all_u8(&addr);
        }
    };
}
