#ifndef _PARISC_SIGINFO_H
#define _PARISC_SIGINFO_H

<<<<<<< HEAD
#if defined(__LP64__)
#define __ARCH_SI_PREAMBLE_SIZE   (4 * sizeof(int))
#endif

=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
#include <asm-generic/siginfo.h>

#undef NSIGTRAP
#define NSIGTRAP	4

#endif
