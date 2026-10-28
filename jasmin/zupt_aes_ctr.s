# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Generated from jasmin/zupt_aes_ctr.jazz by Jasmin compiler 2026.09.0.
# Source SHA256: dbc2bf0f709b86646c1e590ec07711750c12e4c89b25241b22a8d699a46b1883
	.att_syntax
	.text
	.p2align	5
	.global	zupt_aes256_blk
	.type	zupt_aes256_blk, %function
zupt_aes256_blk:
	movq	%rsp, %r10
	leaq	-240(%rsp), %rsp
	andq	$-16, %rsp
	vmovdqu	(%rdx), %xmm0
	vmovdqu	16(%rdx), %xmm1
	vmovdqu	%xmm0, (%rsp)
	vmovdqu	%xmm1, 16(%rsp)
	vaeskeygenassist	$1, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 32(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 48(%rsp)
	vaeskeygenassist	$2, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 64(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 80(%rsp)
	vaeskeygenassist	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 96(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 112(%rsp)
	vaeskeygenassist	$8, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 128(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 144(%rsp)
	vaeskeygenassist	$16, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 160(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 176(%rsp)
	vaeskeygenassist	$32, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 192(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 208(%rsp)
	vaeskeygenassist	$64, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 224(%rsp)
	vmovdqu	(%rcx), %xmm0
	vpxor	(%rsp), %xmm0, %xmm0
	vaesenc	16(%rsp), %xmm0, %xmm0
	vaesenc	32(%rsp), %xmm0, %xmm0
	vaesenc	48(%rsp), %xmm0, %xmm0
	vaesenc	64(%rsp), %xmm0, %xmm0
	vaesenc	80(%rsp), %xmm0, %xmm0
	vaesenc	96(%rsp), %xmm0, %xmm0
	vaesenc	112(%rsp), %xmm0, %xmm0
	vaesenc	128(%rsp), %xmm0, %xmm0
	vaesenc	144(%rsp), %xmm0, %xmm0
	vaesenc	160(%rsp), %xmm0, %xmm0
	vaesenc	176(%rsp), %xmm0, %xmm0
	vaesenc	192(%rsp), %xmm0, %xmm0
	vaesenc	208(%rsp), %xmm0, %xmm0
	vaesenclast	224(%rsp), %xmm0, %xmm0
	vmovdqu	(%rsi), %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vmovdqu	%xmm0, (%rdi)
	movq	%r10, %rsp
	movq	%rsp, %rsi
	vpxor	%xmm2, %xmm2, %xmm2
	andq	$-16, %rsp
	subq	$240, %rsp
	vmovdqu	%xmm2, 224(%rsp)
	vmovdqu	%xmm2, 208(%rsp)
	vmovdqu	%xmm2, 192(%rsp)
	vmovdqu	%xmm2, 176(%rsp)
	vmovdqu	%xmm2, 160(%rsp)
	vmovdqu	%xmm2, 144(%rsp)
	vmovdqu	%xmm2, 128(%rsp)
	vmovdqu	%xmm2, 112(%rsp)
	vmovdqu	%xmm2, 96(%rsp)
	vmovdqu	%xmm2, 80(%rsp)
	vmovdqu	%xmm2, 64(%rsp)
	vmovdqu	%xmm2, 48(%rsp)
	vmovdqu	%xmm2, 32(%rsp)
	vmovdqu	%xmm2, 16(%rsp)
	vmovdqu	%xmm2, (%rsp)
	movq	%rsi, %rsp
	ret
	.ident	"Jasmin Compiler 2026.09.0"
	.section	".note.GNU-stack", "", %progbits
