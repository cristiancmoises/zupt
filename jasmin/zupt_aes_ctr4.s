# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Generated from jasmin/zupt_aes_ctr4.jazz by Jasmin compiler 2026.09.0.
# Source SHA256: 9643e00f5b838b91325086a450ac6524544138d5c0a702ed142a2e902f0f2506
	.att_syntax
	.text
	.p2align	5
	.global	zupt_aes256_ctr4
	.type	zupt_aes256_ctr4, %function
zupt_aes256_ctr4:
	movq	%rsp, %r10
	leaq	-256(%rsp), %rsp
	andq	$-16, %rsp
	cmpq	$0, %r8
	je  	.Lzupt_aes256_ctr4$1
	vmovdqu	(%rdx), %xmm0
	vmovdqu	16(%rdx), %xmm1
	vmovdqu	%xmm0, 16(%rsp)
	vmovdqu	%xmm1, 32(%rsp)
	vaeskeygenassist	$1, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 48(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 64(%rsp)
	vaeskeygenassist	$2, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 80(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 96(%rsp)
	vaeskeygenassist	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 112(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 128(%rsp)
	vaeskeygenassist	$8, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 144(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 160(%rsp)
	vaeskeygenassist	$16, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 176(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 192(%rsp)
	vaeskeygenassist	$32, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 208(%rsp)
	vaeskeygenassist	$0, %xmm0, %xmm2
	vpshufd	$170, %xmm2, %xmm2
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm3
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 224(%rsp)
	vaeskeygenassist	$64, %xmm1, %xmm2
	vpshufd	$255, %xmm2, %xmm2
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpslldq	$4, %xmm0, %xmm3
	vpxor	%xmm3, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 240(%rsp)
	movq	(%rcx), %rax
	movq	%rax, (%rsp)
	movq	8(%rcx), %rax
	movq	%rax, 8(%rsp)
	bswapq	%rax
	jmp 	.Lzupt_aes256_ctr4$4
.Lzupt_aes256_ctr4$5:
	vmovdqu	(%rsp), %xmm0
	incq	%rax
	movq	%rax, %rdx
	bswapq	%rdx
	movq	%rdx, 8(%rsp)
	vmovdqu	(%rsp), %xmm1
	incq	%rax
	movq	%rax, %rdx
	bswapq	%rdx
	movq	%rdx, 8(%rsp)
	vmovdqu	(%rsp), %xmm2
	incq	%rax
	movq	%rax, %rdx
	bswapq	%rdx
	movq	%rdx, 8(%rsp)
	vmovdqu	(%rsp), %xmm3
	incq	%rax
	movq	%rax, %rdx
	bswapq	%rdx
	movq	%rdx, 8(%rsp)
	vpxor	16(%rsp), %xmm0, %xmm0
	vpxor	16(%rsp), %xmm1, %xmm1
	vpxor	16(%rsp), %xmm2, %xmm2
	vpxor	16(%rsp), %xmm3, %xmm3
	vaesenc	32(%rsp), %xmm0, %xmm0
	vaesenc	32(%rsp), %xmm1, %xmm1
	vaesenc	32(%rsp), %xmm2, %xmm2
	vaesenc	32(%rsp), %xmm3, %xmm3
	vaesenc	48(%rsp), %xmm0, %xmm0
	vaesenc	48(%rsp), %xmm1, %xmm1
	vaesenc	48(%rsp), %xmm2, %xmm2
	vaesenc	48(%rsp), %xmm3, %xmm3
	vaesenc	64(%rsp), %xmm0, %xmm0
	vaesenc	64(%rsp), %xmm1, %xmm1
	vaesenc	64(%rsp), %xmm2, %xmm2
	vaesenc	64(%rsp), %xmm3, %xmm3
	vaesenc	80(%rsp), %xmm0, %xmm0
	vaesenc	80(%rsp), %xmm1, %xmm1
	vaesenc	80(%rsp), %xmm2, %xmm2
	vaesenc	80(%rsp), %xmm3, %xmm3
	vaesenc	96(%rsp), %xmm0, %xmm0
	vaesenc	96(%rsp), %xmm1, %xmm1
	vaesenc	96(%rsp), %xmm2, %xmm2
	vaesenc	96(%rsp), %xmm3, %xmm3
	vaesenc	112(%rsp), %xmm0, %xmm0
	vaesenc	112(%rsp), %xmm1, %xmm1
	vaesenc	112(%rsp), %xmm2, %xmm2
	vaesenc	112(%rsp), %xmm3, %xmm3
	vaesenc	128(%rsp), %xmm0, %xmm0
	vaesenc	128(%rsp), %xmm1, %xmm1
	vaesenc	128(%rsp), %xmm2, %xmm2
	vaesenc	128(%rsp), %xmm3, %xmm3
	vaesenc	144(%rsp), %xmm0, %xmm0
	vaesenc	144(%rsp), %xmm1, %xmm1
	vaesenc	144(%rsp), %xmm2, %xmm2
	vaesenc	144(%rsp), %xmm3, %xmm3
	vaesenc	160(%rsp), %xmm0, %xmm0
	vaesenc	160(%rsp), %xmm1, %xmm1
	vaesenc	160(%rsp), %xmm2, %xmm2
	vaesenc	160(%rsp), %xmm3, %xmm3
	vaesenc	176(%rsp), %xmm0, %xmm0
	vaesenc	176(%rsp), %xmm1, %xmm1
	vaesenc	176(%rsp), %xmm2, %xmm2
	vaesenc	176(%rsp), %xmm3, %xmm3
	vaesenc	192(%rsp), %xmm0, %xmm0
	vaesenc	192(%rsp), %xmm1, %xmm1
	vaesenc	192(%rsp), %xmm2, %xmm2
	vaesenc	192(%rsp), %xmm3, %xmm3
	vaesenc	208(%rsp), %xmm0, %xmm0
	vaesenc	208(%rsp), %xmm1, %xmm1
	vaesenc	208(%rsp), %xmm2, %xmm2
	vaesenc	208(%rsp), %xmm3, %xmm3
	vaesenc	224(%rsp), %xmm0, %xmm0
	vaesenc	224(%rsp), %xmm1, %xmm1
	vaesenc	224(%rsp), %xmm2, %xmm2
	vaesenc	224(%rsp), %xmm3, %xmm3
	vaesenclast	240(%rsp), %xmm0, %xmm0
	vaesenclast	240(%rsp), %xmm1, %xmm1
	vaesenclast	240(%rsp), %xmm2, %xmm2
	vaesenclast	240(%rsp), %xmm3, %xmm3
	vmovdqu	(%rsi), %xmm4
	vmovdqu	16(%rsi), %xmm5
	vmovdqu	32(%rsi), %xmm6
	vmovdqu	48(%rsi), %xmm7
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm6, %xmm2, %xmm2
	vpxor	%xmm7, %xmm3, %xmm3
	vmovdqu	%xmm0, (%rdi)
	vmovdqu	%xmm1, 16(%rdi)
	vmovdqu	%xmm2, 32(%rdi)
	vmovdqu	%xmm3, 48(%rdi)
	addq	$64, %rsi
	addq	$64, %rdi
	addq	$-4, %r8
.Lzupt_aes256_ctr4$4:
	cmpq	$4, %r8
	jnb 	.Lzupt_aes256_ctr4$5
	jmp 	.Lzupt_aes256_ctr4$2
.Lzupt_aes256_ctr4$3:
	vmovdqu	(%rsp), %xmm0
	vpxor	16(%rsp), %xmm0, %xmm0
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
	vaesenc	224(%rsp), %xmm0, %xmm0
	vaesenclast	240(%rsp), %xmm0, %xmm0
	vmovdqu	(%rsi), %xmm4
	vpxor	%xmm4, %xmm0, %xmm0
	vmovdqu	%xmm0, (%rdi)
	incq	%rax
	movq	%rax, %rdx
	bswapq	%rdx
	movq	%rdx, 8(%rsp)
	addq	$16, %rsi
	addq	$16, %rdi
	decq	%r8
.Lzupt_aes256_ctr4$2:
	cmpq	$0, %r8
	jne 	.Lzupt_aes256_ctr4$3
	vmovdqu	(%rsp), %xmm0
	vmovdqu	%xmm0, (%rcx)
.Lzupt_aes256_ctr4$1:
	movq	%r10, %rsp
	movq	%rsp, %rsi
	vpxor	%xmm2, %xmm2, %xmm2
	andq	$-16, %rsp
	subq	$256, %rsp
	vmovdqu	%xmm2, 240(%rsp)
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
