	.intel_syntax noprefix
	.text
	.p2align	5
	.global	zupt_aes256_blk
	.type	zupt_aes256_blk, %function
zupt_aes256_blk:
	mov 	r10, rsp
	lea 	rsp, qword ptr[rsp + -240]
	and 	rsp, -16
	vmovdqu	xmm0, xmmword ptr[rdx]
	vmovdqu	xmm1, xmmword ptr[rdx + 1]
	vmovdqu	xmmword ptr[rsp], xmm0
	vmovdqu	xmmword ptr[rsp + 1], xmm1
	vaeskeygenassist	xmm2, xmm1, 1
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 2], xmm0
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 170
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqu	xmmword ptr[rsp + 3], xmm1
	vaeskeygenassist	xmm2, xmm1, 2
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 4], xmm0
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 170
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqu	xmmword ptr[rsp + 5], xmm1
	vaeskeygenassist	xmm2, xmm1, 4
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 6], xmm0
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 170
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqu	xmmword ptr[rsp + 7], xmm1
	vaeskeygenassist	xmm2, xmm1, 8
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 8], xmm0
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 170
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqu	xmmword ptr[rsp + 9], xmm1
	vaeskeygenassist	xmm2, xmm1, 16
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 10], xmm0
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 170
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqu	xmmword ptr[rsp + 11], xmm1
	vaeskeygenassist	xmm2, xmm1, 32
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 12], xmm0
	vaeskeygenassist	xmm2, xmm0, 0
	vpshufd	xmm2, xmm2, 170
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpslldq	xmm3, xmm1, 4
	vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
	vmovdqu	xmmword ptr[rsp + 13], xmm1
	vaeskeygenassist	xmm2, xmm1, 64
	vpshufd	xmm2, xmm2, 255
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpslldq	xmm3, xmm0, 4
	vpxor	xmm0, xmm0, xmm3
	vpxor	xmm0, xmm0, xmm2
	vmovdqu	xmmword ptr[rsp + 14], xmm0
	vmovdqu	xmm0, xmmword ptr[rcx]
	vpxor	xmm0, xmm0, xmmword ptr[rsp]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 1]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 2]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 3]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 4]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 5]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 6]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 7]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 8]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 9]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 10]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 11]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 12]
	vaesenc	xmm0, xmm0, xmmword ptr[rsp + 13]
	vaesenclast	xmm0, xmm0, xmmword ptr[rsp + 14]
	vmovdqu	xmm1, xmmword ptr[rsi]
	vpxor	xmm0, xmm0, xmm1
	movq	qword ptr[rdi], xmm0
	mov 	rsp, r10
	ret
	.ident	"Jasmin Compiler 2026.03.0"
	.section	".note.GNU-stack", "", %progbits
