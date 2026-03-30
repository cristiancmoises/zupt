	.intel_syntax noprefix
	.text
	.p2align	5
	.global	zupt_aes256_ctr4
	.type	zupt_aes256_ctr4, %function
/* zupt_aes256_ctr4(out=rdi, in=rsi, key=rdx, ctr=rcx, nblocks=r8)
 *
 * AES-256-CTR with 4-block interleaving for pipeline saturation.
 * Processes 4 blocks per loop iteration. Remaining 1-3 blocks
 * processed one at a time.
 *
 * AES-NI latency=4 cycles, throughput=1 cycle/block.
 * 4 independent blocks → 4 AESENC in flight → ~4× throughput.
 *
 * Counter: big-endian increment in bytes [8..15] of the 16-byte block.
 */
zupt_aes256_ctr4:
	push	rbx
	push	r12
	push	r13
	mov	r12, r8			/* nblocks */
	test	r12, r12
	jz	.Ldone

	/* Load 256-bit key into xmm14, xmm15 */
	vmovdqu	xmm14, xmmword ptr[rdx]
	vmovdqu	xmm15, xmmword ptr[rdx + 16]

	/* Load counter template */
	vmovdqu	xmm13, xmmword ptr[rcx]

	/* Byte-swap mask for big-endian counter increment */
	/* We increment a 64-bit big-endian value in bytes [8..15] */

.Lloop4:
	cmp	r12, 4
	jb	.Lloop1

	/* ═══ Generate 4 counter blocks with sequential values ═══ */
	vmovdqa	xmm0, xmm13		/* ctr+0 */

	/* Increment counter: byte-swap last 8 bytes, add 1, swap back */
	/* Simple approach: store to stack, increment, reload */
	sub	rsp, 64
	vmovdqa	xmmword ptr[rsp], xmm13
	/* Increment the big-endian counter in bytes [8..15] */
	mov	rax, qword ptr[rsp + 8]
	bswap	rax
	lea	rbx, [rax + 1]
	bswap	rbx
	mov	qword ptr[rsp + 8], rbx
	vmovdqa	xmm1, xmmword ptr[rsp]	/* ctr+1 */

	bswap	rbx
	lea	r13, [rbx + 1]
	bswap	r13
	mov	qword ptr[rsp + 8], r13
	vmovdqa	xmm2, xmmword ptr[rsp]	/* ctr+2 */

	bswap	r13
	lea	rbx, [r13 + 1]
	bswap	rbx
	mov	qword ptr[rsp + 8], rbx
	vmovdqa	xmm3, xmmword ptr[rsp]	/* ctr+3 */

	/* Update counter template to ctr+4 */
	bswap	rbx
	add	rbx, 1
	bswap	rbx
	mov	qword ptr[rsp + 8], rbx
	vmovdqa	xmm13, xmmword ptr[rsp]
	add	rsp, 64

	/* ═══ Key expansion + 14-round AES-256 on 4 blocks ═══ */
	/* Round 0: AddRoundKey with key[0] */
	vpxor	xmm0, xmm0, xmm14
	vpxor	xmm1, xmm1, xmm14
	vpxor	xmm2, xmm2, xmm14
	vpxor	xmm3, xmm3, xmm14

	/* We need round keys 1-14. For the 4-block pipeline, we compute
	 * each round key once and apply it to all 4 blocks before moving
	 * to the next round. This amortizes key expansion cost. */

	/* For simplicity and correctness, we expand all 15 round keys
	 * on the stack first, then apply them to all 4 blocks. */
	sub	rsp, 240

	/* Store rk0 = key[0], rk1 = key[1] */
	vmovdqa	xmmword ptr[rsp + 0], xmm14
	vmovdqa	xmmword ptr[rsp + 16], xmm15

	/* Expand remaining round keys (same logic as zupt_aes_ctr.s) */
	vmovdqa	xmm4, xmm14		/* t0 */
	vmovdqa	xmm5, xmm15		/* t1 */

	.macro EXPAND_EVEN rcon, offset
	vaeskeygenassist	xmm6, xmm5, \rcon
	vpshufd	xmm6, xmm6, 0xFF
	vpslldq	xmm7, xmm4, 4
	vpxor	xmm4, xmm4, xmm7
	vpslldq	xmm7, xmm4, 4
	vpxor	xmm4, xmm4, xmm7
	vpslldq	xmm7, xmm4, 4
	vpxor	xmm4, xmm4, xmm7
	vpxor	xmm4, xmm4, xmm6
	vmovdqa	xmmword ptr[rsp + \offset], xmm4
	.endm

	.macro EXPAND_ODD offset
	vaeskeygenassist	xmm6, xmm4, 0
	vpshufd	xmm6, xmm6, 0xAA
	vpslldq	xmm7, xmm5, 4
	vpxor	xmm5, xmm5, xmm7
	vpslldq	xmm7, xmm5, 4
	vpxor	xmm5, xmm5, xmm7
	vpslldq	xmm7, xmm5, 4
	vpxor	xmm5, xmm5, xmm7
	vpxor	xmm5, xmm5, xmm6
	vmovdqa	xmmword ptr[rsp + \offset], xmm5
	.endm

	EXPAND_EVEN 0x01, 32
	EXPAND_ODD 48
	EXPAND_EVEN 0x02, 64
	EXPAND_ODD 80
	EXPAND_EVEN 0x04, 96
	EXPAND_ODD 112
	EXPAND_EVEN 0x08, 128
	EXPAND_ODD 144
	EXPAND_EVEN 0x10, 160
	EXPAND_ODD 176
	EXPAND_EVEN 0x20, 192
	EXPAND_ODD 208
	EXPAND_EVEN 0x40, 224

	/* ═══ Apply rounds 1-13 to all 4 blocks (interleaved) ═══ */
	.macro ROUND4 offset
	vmovdqa	xmm8, xmmword ptr[rsp + \offset]
	vaesenc	xmm0, xmm0, xmm8
	vaesenc	xmm1, xmm1, xmm8
	vaesenc	xmm2, xmm2, xmm8
	vaesenc	xmm3, xmm3, xmm8
	.endm

	ROUND4 16	/* Round 1 */
	ROUND4 32	/* Round 2 */
	ROUND4 48	/* Round 3 */
	ROUND4 64	/* Round 4 */
	ROUND4 80	/* Round 5 */
	ROUND4 96	/* Round 6 */
	ROUND4 112	/* Round 7 */
	ROUND4 128	/* Round 8 */
	ROUND4 144	/* Round 9 */
	ROUND4 160	/* Round 10 */
	ROUND4 176	/* Round 11 */
	ROUND4 192	/* Round 12 */
	ROUND4 208	/* Round 13 */

	/* Round 14 (final) */
	vmovdqa	xmm8, xmmword ptr[rsp + 224]
	vaesenclast	xmm0, xmm0, xmm8
	vaesenclast	xmm1, xmm1, xmm8
	vaesenclast	xmm2, xmm2, xmm8
	vaesenclast	xmm3, xmm3, xmm8

	/* Wipe round keys */
	vpxor	xmm8, xmm8, xmm8
	.irp off, 0,16,32,48,64,80,96,112,128,144,160,176,192,208,224
	vmovdqa	xmmword ptr[rsp + \off], xmm8
	.endr
	add	rsp, 240

	/* XOR keystreams with plaintext */
	vpxor	xmm0, xmm0, xmmword ptr[rsi]
	vpxor	xmm1, xmm1, xmmword ptr[rsi + 16]
	vpxor	xmm2, xmm2, xmmword ptr[rsi + 32]
	vpxor	xmm3, xmm3, xmmword ptr[rsi + 48]

	/* Store results */
	vmovdqu	xmmword ptr[rdi], xmm0
	vmovdqu	xmmword ptr[rdi + 16], xmm1
	vmovdqu	xmmword ptr[rdi + 32], xmm2
	vmovdqu	xmmword ptr[rdi + 48], xmm3

	add	rsi, 64
	add	rdi, 64
	sub	r12, 4
	jmp	.Lloop4

.Lloop1:
	test	r12, r12
	jz	.Ldone

	/* Single-block fallback for remaining 1-3 blocks */
	/* Expand keys on stack (reuse zupt_aes256_blk logic) */
	sub	rsp, 256
	and	rsp, -16

	vmovdqa	xmm4, xmm14
	vmovdqa	xmm5, xmm15
	vmovdqa	xmmword ptr[rsp + 0], xmm4
	vmovdqa	xmmword ptr[rsp + 16], xmm5

	EXPAND_EVEN 0x01, 32
	EXPAND_ODD 48
	EXPAND_EVEN 0x02, 64
	EXPAND_ODD 80
	EXPAND_EVEN 0x04, 96
	EXPAND_ODD 112
	EXPAND_EVEN 0x08, 128
	EXPAND_ODD 144
	EXPAND_EVEN 0x10, 160
	EXPAND_ODD 176
	EXPAND_EVEN 0x20, 192
	EXPAND_ODD 208
	EXPAND_EVEN 0x40, 224

.Lsingle:
	vmovdqa	xmm0, xmm13
	vpxor	xmm0, xmm0, xmmword ptr[rsp + 0]
	.irp off, 16,32,48,64,80,96,112,128,144,160,176,192,208
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + \off]
	.endr
	vaesenclast	xmm0, xmm0, xmmword ptr[rsp + 224]

	vpxor	xmm0, xmm0, xmmword ptr[rsi]
	vmovdqu	xmmword ptr[rdi], xmm0

	/* Increment counter */
	sub	rsp, 16
	vmovdqa	xmmword ptr[rsp], xmm13
	mov	rax, qword ptr[rsp + 8]
	bswap	rax
	add	rax, 1
	bswap	rax
	mov	qword ptr[rsp + 8], rax
	vmovdqa	xmm13, xmmword ptr[rsp]
	add	rsp, 16

	add	rsi, 16
	add	rdi, 16
	dec	r12
	jnz	.Lsingle

	/* Wipe round keys */
	vpxor	xmm8, xmm8, xmm8
	.irp off, 0,16,32,48,64,80,96,112,128,144,160,176,192,208,224
	vmovdqa	xmmword ptr[rsp + \off], xmm8
	.endr
	add	rsp, 256

.Ldone:
	/* Store updated counter back */
	vmovdqu	xmmword ptr[rcx], xmm13

	pop	r13
	pop	r12
	pop	rbx
	ret
	.size	zupt_aes256_ctr4, . - zupt_aes256_ctr4

	.section .note.GNU-stack,"",@progbits
