#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
# include <windows.h>
#elif defined(HAVE_PTHREAD)
# include <pthread.h>
#endif

#include "core.h"
#include "sr25519-randombytes-default.h"

static volatile int initialized;
static volatile int locked;

#ifdef _WIN32

static CRITICAL_SECTION _sodium_lock;
static volatile LONG    _sodium_lock_initialized;

int
_sodium_crit_init(void)
{
    LONG status = 0L;

    while ((status = InterlockedCompareExchange(&_sodium_lock_initialized,
                                                1L, 0L)) == 1L) {
        Sleep(0);
    }

    switch (status) {
    case 0L:
        InitializeCriticalSection(&_sodium_lock);
        return InterlockedExchange(&_sodium_lock_initialized, 2L) == 1L ? 0 : -1;
    case 2L:
        return 0;
    default: /* should never be reached */
        return -1;
    }
}

int
sodium_crit_enter(void)
{
    if (_sodium_crit_init() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    EnterCriticalSection(&_sodium_lock);
    assert(locked == 0);
    locked = 1;

    return 0;
}

int
sodium_crit_leave(void)
{
    if (locked == 0) {
# ifdef EPERM
        errno = EPERM;
# endif
        return -1;
    }
    locked = 0;
    LeaveCriticalSection(&_sodium_lock);

    return 0;
}

#elif defined(HAVE_PTHREAD) && !defined(__EMSCRIPTEN__)

static pthread_mutex_t _sodium_lock = PTHREAD_MUTEX_INITIALIZER;

int
sodium_crit_enter(void)
{
    int ret;

    if ((ret = pthread_mutex_lock(&_sodium_lock)) == 0) {
        assert(locked == 0);
        locked = 1;
    }
    return ret;
}

int
sodium_crit_leave(void)
{
    if (locked == 0) {
# ifdef EPERM
        errno = EPERM;
# endif
        return -1;
    }
    locked = 0;

    return pthread_mutex_unlock(&_sodium_lock);
}

#elif defined(HAVE_ATOMIC_OPS) && !defined(__EMSCRIPTEN__)

static volatile int _sodium_lock;

int
sodium_crit_enter(void)
{
# ifdef HAVE_NANOSLEEP
    struct timespec q;
    memset(&q, 0, sizeof q);
# endif
    while (__sync_lock_test_and_set(&_sodium_lock, 1) != 0) {
# ifdef HAVE_NANOSLEEP
        (void) nanosleep(&q, NULL);
# elif defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__ ("pause");
# endif
    }
    return 0;
}

int
sodium_crit_leave(void)
{
    __sync_lock_release(&_sodium_lock);

    return 0;
}

#else

int
sodium_crit_enter(void)
{
    return 0;
}

int
sodium_crit_leave(void)
{
    return 0;
}

#endif

static void (*_misuse_handler)(void);

void
sodium_misuse(void)
{
    void (*handler)(void);

    (void) sodium_crit_leave();
    if (sodium_crit_enter() == 0) {
        handler = _misuse_handler;
        if (handler != NULL) {
            handler();
        }
    }
/* LCOV_EXCL_START */
    abort();
}
/* LCOV_EXCL_STOP */
