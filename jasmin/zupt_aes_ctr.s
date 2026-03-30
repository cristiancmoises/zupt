	.intel_syntax noprefix
	.text
	.p2align	5
	.global	zupt_aes256_blk
	.type	zupt_aes256_blk, %function
/* zupt_aes256_blk(out_ptr=rdi, in_blk=rsi, key=rdx, ctr_blk=rcx)
 * AES-256 single-block encrypt: out = AES(key, ctr) XOR in
 *
 * FIX v2.0.0: Round keys at [rsp+0], [rsp+16], [rsp+32], ..., [rsp+224]
 * The previous version had [rsp+0], [rsp+1], ..., [rsp+14] (byte offsets).
 *
 * Stack layout: 15 × 16 bytes = 240 bytes for round keys, 16-byte aligned.
 */
zupt_aes256_blk:
	mov 	r10, rsp
	lea 	rsp, qword ptr[rsp - 256]
	and 	rsp, -16

	/* Load 256-bit key (two u128 halves) */
	vmovdqu	xmm0, xmmword ptr[rdx]        /* key[0] = first 128 bits */
	vmovdqu	xmm1, xmmword ptr[rdx + 16]   /* key[1] = second 128 bits */

	/* Store round keys 0-1 (the raw key halves) */
	vmovdqa	xmmword ptr[rsp + 0], xmm0     /* rk0 */
	vmovdqa	xmmword ptr[rsp + 16], xmm1    /* rk1 */

	/* Round key 2 (even): RCON=0x01 */
	vaeskeygenassist	xmm2, xmm1, 0x01
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 32], xmm0    /* rk2 */

	/* Round key 3 (odd) */
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 0xAA
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqa	xmmword ptr[rsp + 48], xmm1    /* rk3 */

	/* Round key 4 (even): RCON=0x02 */
	vaeskeygenassist	xmm2, xmm1, 0x02
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 64], xmm0    /* rk4 */

	/* Round key 5 (odd) */
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 0xAA
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqa	xmmword ptr[rsp + 80], xmm1    /* rk5 */

	/* Round key 6 (even): RCON=0x04 */
	vaeskeygenassist	xmm2, xmm1, 0x04
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 96], xmm0    /* rk6 */

	/* Round key 7 (odd) */
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 0xAA
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqa	xmmword ptr[rsp + 112], xmm1   /* rk7 */

	/* Round key 8 (even): RCON=0x08 */
	vaeskeygenassist	xmm2, xmm1, 0x08
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 128], xmm0   /* rk8 */

	/* Round key 9 (odd) */
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 0xAA
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqa	xmmword ptr[rsp + 144], xmm1   /* rk9 */

	/* Round key 10 (even): RCON=0x10 */
	vaeskeygenassist	xmm2, xmm1, 0x10
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 160], xmm0   /* rk10 */

	/* Round key 11 (odd) */
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 0xAA
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqa	xmmword ptr[rsp + 176], xmm1   /* rk11 */

	/* Round key 12 (even): RCON=0x20 */
	vaeskeygenassist	xmm2, xmm1, 0x20
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 192], xmm0   /* rk12 */

	/* Round key 13 (odd) */
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 0xAA
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqa	xmmword ptr[rsp + 208], xmm1   /* rk13 */

	/* Round key 14 (even): RCON=0x40 */
	vaeskeygenassist	xmm2, xmm1, 0x40
	vpshufd	xmm2, xmm2, 0xFF
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqa	xmmword ptr[rsp + 224], xmm0   /* rk14 */

	/* ═══ Encrypt: AES-256 14 rounds ═══ */
	vmovdqu	xmm4, xmmword ptr[rcx]         /* Load counter block */
	vpxor	xmm4, xmm4, xmmword ptr[rsp + 0]    /* AddRoundKey(rk0) */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 16]   /* Round 1 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 32]   /* Round 2 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 48]   /* Round 3 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 64]   /* Round 4 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 80]   /* Round 5 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 96]   /* Round 6 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 112]  /* Round 7 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 128]  /* Round 8 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 144]  /* Round 9 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 160]  /* Round 10 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 176]  /* Round 11 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 192]  /* Round 12 */
	vaesenc	xmm4, xmm4, xmmword ptr[rsp + 208]  /* Round 13 */
	vaesenclast	xmm4, xmm4, xmmword ptr[rsp + 224] /* Round 14 (final) */

	/* XOR keystream with plaintext */
	vmovdqu	xmm5, xmmword ptr[rsi]         /* Load plaintext block */
	vpxor	xmm4, xmm4, xmm5
	vmovdqu	xmmword ptr[rdi], xmm4         /* Store result */

	/* Wipe round keys from stack */
	vpxor	xmm0, xmm0, xmm0
	vmovdqa	xmmword ptr[rsp + 0], xmm0
	vmovdqa	xmmword ptr[rsp + 16], xmm0
	vmovdqa	xmmword ptr[rsp + 32], xmm0
	vmovdqa	xmmword ptr[rsp + 48], xmm0
	vmovdqa	xmmword ptr[rsp + 64], xmm0
	vmovdqa	xmmword ptr[rsp + 80], xmm0
	vmovdqa	xmmword ptr[rsp + 96], xmm0
	vmovdqa	xmmword ptr[rsp + 112], xmm0
	vmovdqa	xmmword ptr[rsp + 128], xmm0
	vmovdqa	xmmword ptr[rsp + 144], xmm0
	vmovdqa	xmmword ptr[rsp + 160], xmm0
	vmovdqa	xmmword ptr[rsp + 176], xmm0
	vmovdqa	xmmword ptr[rsp + 192], xmm0
	vmovdqa	xmmword ptr[rsp + 208], xmm0
	vmovdqa	xmmword ptr[rsp + 224], xmm0

	mov 	rsp, r10
	ret
	.size	zupt_aes256_blk, . - zupt_aes256_blk

	.section .note.GNU-stack,"",@progbits
