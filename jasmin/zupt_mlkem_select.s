	.intel_syntax noprefix
	.text
	.p2align	5
	.global	zupt_ct_select_32
	.type	zupt_ct_select_32, %function
zupt_ct_select_32:
	mov 	rax, 0
	sub 	rax, rcx
	mov 	rcx, qword ptr[rsi]
	mov 	r8, qword ptr[rdx]
	mov 	r9, rcx
	xor 	r9, r8
	and 	r9, rax
	xor 	rcx, r9
	mov 	qword ptr[rdi], rcx
	mov 	rcx, qword ptr[rsi + 8]
	mov 	r8, qword ptr[rdx + 8]
	mov 	r9, rcx
	xor 	r9, r8
	and 	r9, rax
	xor 	rcx, r9
	mov 	qword ptr[rdi + 8], rcx
	mov 	rcx, qword ptr[rsi + 16]
	mov 	r8, qword ptr[rdx + 16]
	mov 	r9, rcx
	xor 	r9, r8
	and 	r9, rax
	xor 	rcx, r9
	mov 	qword ptr[rdi + 16], rcx
	mov 	rcx, qword ptr[rsi + 24]
	mov 	r8, qword ptr[rdx + 24]
	mov 	r9, rcx
	xor 	r9, r8
	and 	r9, rax
	xor 	rcx, r9
	mov 	qword ptr[rdi + 24], rcx
	ret
	.ident	"Jasmin Compiler 2026.03.0"
	.section	".note.GNU-stack", "", %progbits
