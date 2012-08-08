BITS 32

section .text

global _start
_start:
	pushad
	xor	dword	ebx, ebx
	push	dword	0x0a786148 ; "Hax\n"
	mov	dword	ecx, esp
	mul	dword	ebx
	inc	dword	ebx
	mov	byte	dl, 0x4
	mov	byte	al, 0x4
	int		0x80
	pop	long	esi
	popad
	mov	long	eax, 0xdeadbeef ; Will be replaced with original entry point
	jmp	long	eax
