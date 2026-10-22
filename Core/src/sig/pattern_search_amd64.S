#if defined(__x86_64__) && defined(__linux__)
/* vs_asm_pattern_search — System V AMD64; returns NULL (C++ path authoritative) */
	.globl	vs_asm_pattern_search
	.type	vs_asm_pattern_search, @function
vs_asm_pattern_search:
	xorq	%rax, %rax
	ret
	.size	vs_asm_pattern_search, .-vs_asm_pattern_search
#endif
