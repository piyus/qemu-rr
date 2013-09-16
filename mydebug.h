#ifndef MYDEBUG_H
#define MYDEBUG_H
#include <assert.h>

#ifndef NDEBUG
#define ASSERT(x) do { if (!(x)) { mybacktrace(); } assert(x); } while(0)
#else
#define ASSERT(...)
#endif

#define NOT_REACHED() do { printf("Not reached.\n"); ASSERT(0); } while(0)
#define NOT_IMPLEMENTED() do { printf("Not implemented.\n"); ASSERT(0); } while(0)

/* GCC lets us add "attributes" to functions, function
 * parameters, etc. to indicate their properties.
 * See the GCC manual for details. */
#define UNUSED __attribute__ ((unused))
#define NO_RETURN __attribute__ ((noreturn))
#define NO_INLINE __attribute__ ((noinline))
#define PRINTF_FORMAT(FMT, FIRST) __attribute__ ((format (printf, FMT, FIRST)))

#define PANIC(x) ASSERT(0)

#define unique_backtrace() do { \
  static void *bt_seen[100][100]; \
  static int bt_seen_depth[100]; \
  static int n = 0; \
  int i, seen_before = 0; \
  bt_seen_depth[n] = backtrace(bt_seen[n], sizeof bt_seen[n]); \
  for (i = 0; i < n; i++) {                                    \
    if (!memcmp(bt_seen[i], bt_seen[n], bt_seen_depth[n]*sizeof(bt_seen[0][0]))) {   \
      seen_before = 1; \
    }                                                          \
  } \
  if (!seen_before) { \
    mybacktrace(); \
    n++; \
  } \
} while (0)

void mybacktrace(void);

#include <stdbool.h>
extern bool start_logging;
#endif /* mydebug.h */
