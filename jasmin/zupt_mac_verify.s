	.intel_syntax noprefix
	.text
	.p2align	5
	.global	zupt_mac_verify_ct
	.type	zupt_mac_verify_ct, %function
zupt_mac_verify_ct:
	mov 	rax, 0
	mov 	rcx, qword ptr[rdi]
	mov 	rdx, qword ptr[rsi]
	xor 	rcx, rdx
	or  	rax, rcx
	mov 	rcx, qword ptr[rdi + 8]
	mov 	rdx, qword ptr[rsi + 8]
	xor 	rcx, rdx
	or  	rax, rcx
	mov 	rcx, qword ptr[rdi + 16]
	mov 	rdx, qword ptr[rsi + 16]
	xor 	rcx, rdx
	or  	rax, rcx
	mov 	rcx, qword ptr[rdi + 24]
	mov 	rdx, qword ptr[rsi + 24]
	xor 	rcx, rdx
	or  	rax, rcx
	ret
	.ident	"Jasmin Compiler 2026.03.0"
	.section	".note.GNU-stack", "", %progbits
