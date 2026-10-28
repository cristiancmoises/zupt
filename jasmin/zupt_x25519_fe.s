# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Generated from jasmin/zupt_x25519_fe.jazz by Jasmin compiler 2026.09.0.
# Source SHA256: 085e91aebb52eea5db509465293f01b3f49108cad9fa13667a838242350ebab0
	.att_syntax
	.text
	.p2align	5
	.global	zupt_fe_cswap
	.type	zupt_fe_cswap, %function
zupt_fe_cswap:
	movq	$0, %rax
	subq	%rdx, %rax
	movq	(%rdi), %rcx
	movq	(%rsi), %rdx
	movq	%rcx, %r8
	xorq	%rdx, %r8
	andq	%rax, %r8
	xorq	%r8, %rcx
	xorq	%r8, %rdx
	movq	%rcx, (%rdi)
	movq	%rdx, (%rsi)
	movq	8(%rdi), %rcx
	movq	8(%rsi), %rdx
	movq	%rcx, %r8
	xorq	%rdx, %r8
	andq	%rax, %r8
	xorq	%r8, %rcx
	xorq	%r8, %rdx
	movq	%rcx, 8(%rdi)
	movq	%rdx, 8(%rsi)
	movq	16(%rdi), %rcx
	movq	16(%rsi), %rdx
	movq	%rcx, %r8
	xorq	%rdx, %r8
	andq	%rax, %r8
	xorq	%r8, %rcx
	xorq	%r8, %rdx
	movq	%rcx, 16(%rdi)
	movq	%rdx, 16(%rsi)
	movq	24(%rdi), %rcx
	movq	24(%rsi), %rdx
	movq	%rcx, %r8
	xorq	%rdx, %r8
	andq	%rax, %r8
	xorq	%r8, %rcx
	xorq	%r8, %rdx
	movq	%rcx, 24(%rdi)
	movq	%rdx, 24(%rsi)
	ret
	.ident	"Jasmin Compiler 2026.09.0"
	.section	".note.GNU-stack", "", %progbits
