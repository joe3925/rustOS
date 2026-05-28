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
#include "mimalloc/internal.h"

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
