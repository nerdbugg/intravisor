/*
 * The code in this file largely originates from the userlandexec code available
 * at https://github.com/bediger4000/userlandexec. The following license and
 * copyright applies.
 * 
 * BSD 3-Clause License
 * 
 * Copyright (c) 2017, Bruce Ediger
 * Copyright 2016, 2017, 2018 Imperial College London
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "load_elf.h"
#include "cvm/log.h"

#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))
#define ALIGNDOWN(k, v) ((unsigned long)(k)&(~((unsigned long)(v)-1)))

static void *memcopy(void *dest, const void *src, unsigned long n);
static void *map_file(char *file_to_map, struct stat* sb);
static void *mmap_file(char *file_to_map, struct stat* sb);
static int copy_in(char *filename, void *address);

#ifdef __linux__ 
#define SHM_ANON "test"
#define SHM_ANON2 "test2"
#endif

void load_elf(char* file_to_map, void *base_addr, encl_map_info* result) {
    char *mapped;
    struct stat sb;
    Elf64_Ehdr *hdr;
    Elf64_Phdr *pdr;
    int i, anywhere;
    void *entry_point = 0;
    unsigned long load_segments_size;
    unsigned int mapflags = MAP_PRIVATE;

    // mapped = map_file(file_to_map, &sb);
    // todo: only mmap first 4k of file?
    mapped = mmap_file(file_to_map, &sb);

    if(mapped < 0) {
        result->base = (void *)-1;
        return;
    }

    int fd = open(file_to_map, O_RDONLY, 0);

    hdr = (Elf64_Ehdr *)mapped;
    pdr = (Elf64_Phdr *)((unsigned long)hdr + hdr->e_phoff);

    Elf64_Shdr *sections = (Elf64_Shdr *)((char *)mapped + hdr->e_shoff);
    Elf64_Sym *symtab = NULL;
    
    result->end_of_ro = 0;
    result->extra_load = 0;

    // note: processing relocs and getting some symbols' value
    for (i = 0; i < hdr->e_shnum; i++) {
        Elf64_Shdr *shdr = (Elf64_Shdr*)(mapped + hdr->e_shoff);
	    int shnum = hdr->e_shnum;

    	Elf64_Shdr *sh_strtab = &shdr[hdr->e_shstrndx];
    	const char *const sh_strtab_p = mapped + sh_strtab->sh_offset;

    	dlog("type: %d, name = %s\n", sections[i].sh_type, sh_strtab_p + sections[i].sh_name);

    	if(strncmp("__cap_relocs", sh_strtab_p + sections[i].sh_name, strlen("__cap_relocs")) == 0) {
    	    if(result->cap_relocs) {
    		    printf("something is wrong, cap_relocs copied already\n");
    	    }
    	    result->cap_relocs = malloc(sections[i].sh_size);
    	    if(result->cap_relocs == NULL) {
    		printf("cannot allocate memory for cap_relocs\n");
    		break;
    	    }
    	    memcpy(result->cap_relocs, mapped + sections[i].sh_offset, sections[i].sh_size);
    	    result->cap_relocs_size = sections[i].sh_size;
        }

        if (sections[i].sh_type == SHT_SYMTAB) {
            Elf64_Sym *symtab = (Elf64_Sym *)(mapped + sections[i].sh_offset);
	        char *strtab = (char *)(mapped + sections[sections[i].sh_link].sh_offset);

            // note: search for certain symbols
	        for(int j =0; j < sections[i].sh_size/sizeof(Elf64_Sym); j++) {
		        Elf64_Sym *ts = (Elf64_Sym *)&symtab[j];
		        if(strcmp("ret_from_monitor", &strtab[ts->st_name]) == 0) {
                    result->ret_point = ts->st_value;
                }

                if(strcmp("syscall_handler", &strtab[ts->st_name]) == 0) {
                    result->syscall_handler = ts->st_value;
                }

                if(strcmp("host_exit", &strtab[ts->st_name]) == 0) {
                result->host_exit = ts->st_value;
                }
	        }

            assert(result->host_exit != NULL);
        }
    }


    // note: compute total in-memory size, load_segments_size
    void *segment_base = 0;
    for (i = 0; i < hdr->e_phnum; ++i) {
        if (pdr[i].p_type != PT_LOAD)
            continue;

        if (!anywhere && pdr[i].p_vaddr == 0) {
            anywhere = 1;  /* map it anywhere, like ld.so, or PIC code. */
        } else if (!anywhere && !segment_base) {
            segment_base = (void*) pdr[i].p_vaddr;
        }

        // Determine total in-memory size of all loadable sections:
        // Virtual address/Offset plus memory size of last loadable segment.
        load_segments_size = (unsigned long) ((void*) pdr[i].p_vaddr - segment_base) + pdr[i].p_memsz;
    }

    if (!anywhere)
        mapflags |= MAP_FIXED;

    entry_point = (void *)hdr->e_entry;

    unsigned long extra = EXTRA_PAYLOAD;
    result->extra_load = extra;
    load_segments_size += extra;

    if(extra>0)
        dlog("Extra payload: old 0x%lx, new 0x%lx\n", ROUNDUP(load_segments_size-extra, 0x1000), load_segments_size);

    // note: reserve the memory region for loading
    size_t total_length = ROUNDUP(load_segments_size, 0x1000);
    void* full = mmap((void*)base_addr, total_length, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0);
    if (full==MAP_FAILED) {
        printf("can not allocate 0x%lx in %p, die\n", total_length, base_addr);
        perror("mmap");
        while(1);
    }

    // note: fill extra memory segment?

    // note: load segments of elf file
    // assme the file is PIC
    for (i = 0; i < hdr->e_phnum; ++i, ++pdr) {
        unsigned int protflags = PROT_EXEC;
        unsigned long map_addr = 0, map_len=0;
        off_t offset;
        void *segment;

        if (pdr->p_type != PT_LOAD)  /* Segment not "loadable" */
            continue;

        if ((pdr->p_flags & PF_W) && (result->end_of_ro==0)) {
            log("end of RO: %p\n", pdr->p_vaddr+full);
            result->end_of_ro = pdr->p_vaddr;
        }

        // note: assume the initial p_vaddr is 0 (PIC)
        unsigned long unaligned_map_addr = (unsigned long)full + (unsigned long)pdr->p_vaddr;
        map_addr = ALIGNDOWN(unaligned_map_addr, 0x1000);
        mapflags |= MAP_FIXED;
        map_len = ROUNDUP(pdr->p_vaddr + pdr->p_memsz, 0x1000) - ALIGNDOWN(pdr->p_vaddr, 0x1000);
        offset = ALIGNDOWN(pdr->p_offset, 0x1000);
        protflags = (((pdr->p_flags&PF_R) ? PROT_READ : 0) |
            ((pdr->p_flags&PF_W) ? PROT_WRITE: 0) |
            ((pdr->p_flags&PF_X) ? PROT_EXEC : 0) );

//todo: we use statically allocated heap in LKL, and memory should be writable and executable because it is used to load the binary. needs to be changed
//      if (pdr->p_flags & PF_W)
#if 0
	    segment = mmap((void *)map_addr, map_len, protflags | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED , sfd, offset);
#else
	    segment = mmap((void *)map_addr, map_len, protflags | PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, offset);
#endif
//	else
//	    segment = mmap((void *)map_addr, map_len, protflags|PROT_EXEC, mapflags , fd, offset);

        if (segment == MAP_FAILED) {
            result->base = (void *)-1;
            fprintf(stderr, "1. Could not map segment (%p) of %s: %s\n", (void*)pdr->p_vaddr, file_to_map, strerror(errno));
	        while(1);
        } else {
	        dlog("Mapped %p, segment = %p, map_aaadr = %p, map_len = %lx\n", (void*)pdr->p_vaddr, segment, map_addr, map_len);
        }

        // note: memset pdr->p_filesz - pdr->p_memsz
        if (pdr->p_memsz > pdr->p_filesz) {
            size_t brk = (size_t)segment + pdr->p_filesz;
            size_t pgbrk = ROUNDUP(brk, 0x1000);

            memset((void *)brk, 0, pgbrk - brk);

            size_t len2 = (size_t)segment + map_len - pgbrk;
            void *mmap_ret1 = mmap((void *)pgbrk, len2, protflags|PROT_EXEC, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);

            if ((pgbrk - (size_t)segment) < map_len && (mmap_ret1 == MAP_FAILED)) {
                result->base = (void *)-1;
                fprintf(stderr, "Could not map segment 1 (%p) of %s: %s\n", (void*)pdr->p_vaddr, file_to_map, strerror(errno));
		        while(1);
            } else
		        printf("SHARED MAPPING %p--%p\n", mmap_ret1, mmap_ret1+len2);
        }
    }

    close(fd);

    result->base = full;
    result->size = load_segments_size;
    result->entry_point = entry_point;

done:
    munmap(mapped, sb.st_size);
}

void *memcopy(void *dest, const void *src, unsigned long n) {
    unsigned long i;
    unsigned char *d = (unsigned char *)dest;
    unsigned char *s = (unsigned char *)src;

    for (i = 0; i < n; ++i)
        d[i] = s[i];

    return dest;
}

void *map_file(char *file_to_map, struct stat* sb) {
    void *mapped;

    if (stat(file_to_map, sb) < 0)
    {
        return (void *)-1;
    }

    mapped = mmap(0, sb->st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mapped == (void *)-1)
    {
		perror("mmap");
        return (void *)-1;
    }

    copy_in(file_to_map, mapped);

    return mapped;
}

void *mmap_file(char *file_to_map, struct stat* sb) {
    void *mapped;
    int fd = open(file_to_map, 0, 0);
    if (fstat(fd, sb) < 0) {
        return MAP_FAILED;
    }

    mapped = mmap(NULL, sb->st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
		perror("mmap");
        return MAP_FAILED;
    }

    return mapped;
}

int copy_in(char *filename, void *address) {
    int fd, cc;
    off_t offset = 0;
    char buf[1024];

    if (0 > (fd = open(filename, 0, 0)))
    {
        return -1;
    }

    while (0 < (cc = read(fd, buf, sizeof(buf))))
    {
        memcpy((void*) ((uintptr_t) address + offset), buf, cc);
        offset += cc;
    }

    close(fd);

    return 0;
}
