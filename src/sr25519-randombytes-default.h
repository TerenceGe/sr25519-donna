#ifndef randombytes_H
#define randombytes_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <sys/types.h>


#if !defined(__clang__) && !defined(__GNUC__)
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

#ifdef SR25519_DONNA_STATIC
# define SR25519_DONNA_EXPORT
# define SR25519_DONNA_EXPORT_WEAK
#else
# if defined(_MSC_VER)
#  ifdef SR25519_DONNA_DLL_EXPORT
#   define SR25519_DONNA_EXPORT __declspec(dllexport)
#  else
#   define SR25519_DONNA_EXPORT __declspec(dllimport)
#  endif
# else
#  if defined(__SUNPRO_C)
#   ifndef __GNU_C__
#    define SR25519_DONNA_EXPORT __attribute__ (visibility(__global))
#   else
#    define SR25519_DONNA_EXPORT __attribute__ __global
#   endif
#  elif defined(_MSG_VER)
#   define SR25519_DONNA_EXPORT extern __declspec(dllexport)
#  else
#   define SR25519_DONNA_EXPORT __attribute__ ((visibility ("default")))
#  endif
# endif
# if defined(__ELF__) && !defined(SR25519_DONNA_DISABLE_WEAK_FUNCTIONS)
#  define SR25519_DONNA_EXPORT_WEAK SR25519_DONNA_EXPORT __attribute__((weak))
# else
#  define SR25519_DONNA_EXPORT_WEAK SR25519_DONNA_EXPORT
# endif
#endif

#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif

#define SR25519_DONNA_MIN(A, B) ((A) < (B) ? (A) : (B))
#define SR25519_DONNA_SIZE_MAX SR25519_DONNA_MIN(UINT64_MAX, SIZE_MAX)

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef struct randombytes_implementation {
    const char *(*implementation_name)(void); /* required */
    uint32_t    (*random)(void);              /* required */
    void        (*stir)(void);                /* optional */
    uint32_t    (*uniform)(const uint32_t upper_bound); /* optional, a default implementation will be used if NULL */
    void        (*buf)(void * const buf, const size_t size); /* required */
    int         (*close)(void);               /* optional */
} randombytes_implementation;

#define randombytes_BYTES_MAX SR25519_DONNA_MIN(SR25519_DONNA_SIZE_MAX, 0xffffffffUL)

#define randombytes_SEEDBYTES 32U
SR25519_DONNA_EXPORT
size_t randombytes_seedbytes(void);

SR25519_DONNA_EXPORT
void randombytes_buf(void * const buf, const size_t size)
            __attribute__ ((nonnull));

/* SR25519_DONNA_EXPORT */
/* void randombytes_buf_deterministic(void * const buf, const size_t size, */
/*                                    const unsigned char seed[randombytes_SEEDBYTES]) */
/*             __attribute__ ((nonnull)); */

SR25519_DONNA_EXPORT
uint32_t randombytes_random(void);

SR25519_DONNA_EXPORT
uint32_t randombytes_uniform(const uint32_t upper_bound);

SR25519_DONNA_EXPORT
void randombytes_stir(void);

SR25519_DONNA_EXPORT
int randombytes_close(void);

SR25519_DONNA_EXPORT
int randombytes_set_implementation(randombytes_implementation *impl)
            __attribute__ ((nonnull));

SR25519_DONNA_EXPORT
const char *randombytes_implementation_name(void);

/* -- NaCl compatibility interface -- */

SR25519_DONNA_EXPORT
void randombytes(unsigned char * const buf, const unsigned long long buf_len)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
