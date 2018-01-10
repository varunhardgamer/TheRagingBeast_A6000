#ifndef __ASM_PARISC_BITSPERLONG_H
#define __ASM_PARISC_BITSPERLONG_H

/*
 * using CONFIG_* outside of __KERNEL__ is wrong,
 * __LP64__ was also removed from headers, so what
 * is the right approach on parisc?
 *	-arnd
 */
#if (defined(__KERNEL__) && defined(CONFIG_64BIT)) || defined (__LP64__)
#define __BITS_PER_LONG 64
<<<<<<< HEAD
#else
#define __BITS_PER_LONG 32
=======
#define SHIFT_PER_LONG 6
#else
#define __BITS_PER_LONG 32
#define SHIFT_PER_LONG 5
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
#endif

#include <asm-generic/bitsperlong.h>

#endif /* __ASM_PARISC_BITSPERLONG_H */
