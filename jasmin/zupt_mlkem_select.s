# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Generated from jasmin/zupt_mlkem_select.jazz by Jasmin compiler 2026.09.0.
# Source SHA256: 2ff9bf26e5358594777a2fd79d0a43f4ac00aa56dcd976d2db5989aa35471c82
	.att_syntax
	.text
	.p2align	5
	.global	zupt_ct_select_32
	.type	zupt_ct_select_32, %function
zupt_ct_select_32:
	movq	$0, %rax
	subq	%rcx, %rax
	movq	(%rsi), %rcx
	movq	(%rdx), %r8
	movq	%rcx, %r9
	xorq	%r8, %r9
	andq	%rax, %r9
	xorq	%r9, %rcx
	movq	%rcx, (%rdi)
	movq	8(%rsi), %rcx
	movq	8(%rdx), %r8
	movq	%rcx, %r9
	xorq	%r8, %r9
	andq	%rax, %r9
	xorq	%r9, %rcx
	movq	%rcx, 8(%rdi)
	movq	16(%rsi), %rcx
	movq	16(%rdx), %r8
	movq	%rcx, %r9
	xorq	%r8, %r9
	andq	%rax, %r9
	xorq	%r9, %rcx
	movq	%rcx, 16(%rdi)
	movq	24(%rsi), %rcx
	movq	24(%rdx), %r8
	movq	%rcx, %r9
	xorq	%r8, %r9
	andq	%rax, %r9
	xorq	%r9, %rcx
	movq	%rcx, 24(%rdi)
	ret
	.ident	"Jasmin Compiler 2026.09.0"
	.section	".note.GNU-stack", "", %progbits
