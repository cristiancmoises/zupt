	.intel_syntax noprefix
	.text
	.p2align	5
	.global	zupt_fe_cswap
	.type	zupt_fe_cswap, %function
zupt_fe_cswap:
	mov 	rax, 0
	sub 	rax, rdx
	mov 	rcx, qword ptr[rdi]
	mov 	rdx, qword ptr[rsi]
	mov 	r8, rcx
	xor 	r8, rdx
	and 	r8, rax
	xor 	rcx, r8
	xor 	rdx, r8
	mov 	qword ptr[rdi], rcx
	mov 	qword ptr[rsi], rdx
	mov 	rcx, qword ptr[rdi + 8]
	mov 	rdx, qword ptr[rsi + 8]
	mov 	r8, rcx
	xor 	r8, rdx
	and 	r8, rax
	xor 	rcx, r8
	xor 	rdx, r8
	mov 	qword ptr[rdi + 8], rcx
	mov 	qword ptr[rsi + 8], rdx
	mov 	rcx, qword ptr[rdi + 16]
	mov 	rdx, qword ptr[rsi + 16]
	mov 	r8, rcx
	xor 	r8, rdx
	and 	r8, rax
	xor 	rcx, r8
	xor 	rdx, r8
	mov 	qword ptr[rdi + 16], rcx
	mov 	qword ptr[rsi + 16], rdx
	mov 	rcx, qword ptr[rdi + 24]
	mov 	rdx, qword ptr[rsi + 24]
	mov 	r8, rcx
	xor 	r8, rdx
	and 	r8, rax
	xor 	rcx, r8
	xor 	rdx, r8
	mov 	qword ptr[rdi + 24], rcx
	mov 	qword ptr[rsi + 24], rdx
	ret
	.ident	"Jasmin Compiler 2026.03.0"
	.section	".note.GNU-stack", "", %progbits
