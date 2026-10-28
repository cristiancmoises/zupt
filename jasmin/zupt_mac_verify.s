# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
# Generated from jasmin/zupt_mac_verify.jazz by Jasmin compiler 2026.09.0.
# Source SHA256: 92ba3664492179ac551a3629dad3c28c716dfd1bd011cb23d56763a0cb97d058
	.att_syntax
	.text
	.p2align	5
	.global	zupt_mac_verify_ct
	.type	zupt_mac_verify_ct, %function
zupt_mac_verify_ct:
	movq	$0, %rax
	movq	(%rdi), %rcx
	movq	(%rsi), %rdx
	xorq	%rdx, %rcx
	orq 	%rcx, %rax
	movq	8(%rdi), %rcx
	movq	8(%rsi), %rdx
	xorq	%rdx, %rcx
	orq 	%rcx, %rax
	movq	16(%rdi), %rcx
	movq	16(%rsi), %rdx
	xorq	%rdx, %rcx
	orq 	%rcx, %rax
	movq	24(%rdi), %rcx
	movq	24(%rsi), %rdx
	xorq	%rdx, %rcx
	orq 	%rcx, %rax
	ret
	.ident	"Jasmin Compiler 2026.09.0"
	.section	".note.GNU-stack", "", %progbits
