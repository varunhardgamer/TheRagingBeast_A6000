/*
 *  linux/arch/arm/lib/copypage.S
 *
 *  Copyright (C) 1995-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  ASM optimised string functions
<<<<<<< HEAD
 *
 *  Optimization for modern ARM platforms
 *  Copyright 2013 Harm Hanemaaijer
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 */
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/cache.h>

<<<<<<< HEAD
/*
 * Notes for armv6/v7:
 * These architectures do not like paired preloads in a 64-byte loop.
 * Instead use a 32-byte loop with one preload per loop on armv6
 * (L1_CACHE_BYTES == 32). On armv7 (L1_CACHE_BYTES == 64), use a
 * 64-byte loop with one preload per loop. In addition, make sure no
 * prefetching happens beyond the source region. The prefetch distance,
 * configured in cache.h, defaults to 3 (96 bytes on armv5/armv6, 192
 * bytes on armv7). This function translates to 16-bit Thumb2
 * instructions whenever possible.
 *
 * This version should work on older platforms as well and is unlikely
 * to degrade performance significantly.
 */

#define COPY_COUNT (PAGE_SZ / (L1_CACHE_BYTES))

		.text
	ARM(	.p2align 5	)
	THUMB(	.p2align 2	)

ENTRY(copy_page)
		stmfd	sp!, {r4-r8, lr}
	PLD(	pld	[r1, #0]		)
	PLD(	pld	[r1, #L1_CACHE_BYTES]		)
		#if PREFETCH_DISTANCE > 2
	PLD(	pld	[r1, #2 * L1_CACHE_BYTES]	)
#if PREFETCH_DISTANCE > 3
	PLD(	pld	[r1, #3 * L1_CACHE_BYTES]	)
#if PREFETCH_DISTANCE > 4
	PLD(	pld	[r1, #4 * L1_CACHE_BYTES]	)
#endif
#endif
#endif
	PLD(	movs	r2, #(COPY_COUNT - PREFETCH_DISTANCE)	)
	NO_PLD(	mov	r2, #COPY_COUNT				)
1:	PLD(	pld	[r1, #PREFETCH_DISTANCE * L1_CACHE_BYTES])
2:
#if L1_CACHE_BYTES == 32
		ldmia	r1!, {r3-r6}
		ldmia   r1!, {r7, r8, ip, lr}
		stmia	r0!, {r3-r6}
		subs	r2, r2, #1
		stmia   r0!, {r7, r8, ip, lr}
#else /* L1_CACHE_BYTES == 64 */
		ldmia   r1!, {r3-r8, ip, lr}
		stmia	r0!, {r3-r8, ip, lr}
		ldmia   r1!, {r3-r8, ip, lr}
		subs	r2, r2, #1
		stmia	r0!, {r3-r8, ip, lr}
#endif
		bgt	1b
	PLD(	cmn	r2, #PREFETCH_DISTANCE	)
	PLD(	bgt	2b			)
		ldmfd	sp!, {r4-r8, pc}
=======
#define COPY_COUNT (PAGE_SZ / (2 * L1_CACHE_BYTES) PLD( -1 ))

		.text
		.align	5
/*
 * StrongARM optimised copy_page routine
 * now 1.78bytes/cycle, was 1.60 bytes/cycle (50MHz bus -> 89MB/s)
 * Note that we probably achieve closer to the 100MB/s target with
 * the core clock switching.
 */
ENTRY(copy_page)
		stmfd	sp!, {r4, lr}			@	2
	PLD(	pld	[r1, #0]		)
	PLD(	pld	[r1, #L1_CACHE_BYTES]		)
		mov	r2, #COPY_COUNT			@	1
		ldmia	r1!, {r3, r4, ip, lr}		@	4+1
1:	PLD(	pld	[r1, #2 * L1_CACHE_BYTES])
	PLD(	pld	[r1, #3 * L1_CACHE_BYTES])
2:
	.rept	(2 * L1_CACHE_BYTES / 16 - 1)
		stmia	r0!, {r3, r4, ip, lr}		@	4
		ldmia	r1!, {r3, r4, ip, lr}		@	4
	.endr
		subs	r2, r2, #1			@	1
		stmia	r0!, {r3, r4, ip, lr}		@	4
		ldmgtia	r1!, {r3, r4, ip, lr}		@	4
		bgt	1b				@	1
	PLD(	ldmeqia r1!, {r3, r4, ip, lr}	)
	PLD(	beq	2b			)
		ldmfd	sp!, {r4, pc}			@	3
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
ENDPROC(copy_page)
