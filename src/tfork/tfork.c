#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <assert.h>

#include "monitor.h"
#include "tfork.h"

#define RET_COMP_PPC (16*11)
#define RET_COMP_DDC (16*12)

const int TFORK_FAILED = MAP_FAILED;
const static int tfork_syscall_num = 577;

struct cvm_tmplt_ctx cvm_ctx[MAX_CVMS];
map_entry* cvm_map_entry_list[MAX_CVMS];
int cvm_snapshot_fd[MAX_CVMS];

int tfork(void *src_addr, void *dst_addr, int len)
{
    return syscall(tfork_syscall_num, src_addr, dst_addr, len);
}

// int checkpoint(void *src_addr, int len, char *filepath)
// {
//     // todo, no-tested
//     int fd = open(filepath, O_RDWR + O_CREAT);
//     for (unsigned int *src = src_addr; src < src_addr + len; ++src)
//     {
//         write(fd, src, sizeof(unsigned int));
//     }
//     close(fd);
// }


unsigned int parse_permstr(char* perms)
{
    unsigned int res = 0;
    if(perms[0] == 'r')
        res |= PROT_READ;
    if(perms[1] == 'w')
        res |= PROT_WRITE;
    if(perms[2] == 'x')
        res |= PROT_EXEC;
    return res;
}

map_entry* get_map_entry_list(int cid)
{
    FILE *map_file = fopen("/proc/curproc/map", "r");
    assert(map_file != NULL);

    map_entry *map_entry_list=NULL, *rear=NULL;

    unsigned long range_low, range_high;
    range_low   = cvms[cid].cmp_begin;
    range_high  = cvms[cid].cmp_end;

    unsigned long start, end;
    int resident, privateresident;
    void* obj;
    char permstr[32] = "";

    char map_buf[256];
    while(fgets(map_buf, sizeof(map_buf), map_file)) {
        int num = sscanf(map_buf, "0x%lx 0x%lx %d %d %p %31s",
                         &start, &end,
                         &resident, &privateresident,
                         &obj, permstr);
        assert(num == 6);

        if(end-1 < range_low)
            continue;
        if(start >= range_high)
            break;

        int prot = parse_permstr(permstr);
        map_entry *entry = (map_entry*)malloc(sizeof(map_entry));
        entry->start= start;
        entry->end  = end;
        entry->prot = prot;
        entry->next = NULL;

        if(map_entry_list==NULL) {
            map_entry_list = entry;
        } else {
            rear->next  = entry;
        }
        rear = entry;
    }
    fclose(map_file);
    return map_entry_list;
}

void free_map_entry_list(map_entry *map_entry_list)
{
    if(map_entry_list==NULL) {
        return;
    }

    map_entry *p = map_entry_list;
    while(p) {
        map_entry *temp=p;
        p = p->next;
        free(temp);
    }
}

void save(int status, int cid, struct c_thread *threads)
{
    void *cur_pc;
    register void *cur_sp asm("sp");
    register void *cur_ra asm("ra");
    register void *cur_s0 asm("s0");
    asm(""
        : "=r"(cur_sp), "=r"(cur_ra), "=r"(cur_s0));
    __asm__ __volatile__("auipc %0, 0"
                         : "=r"(cur_pc));

#ifndef TFORK
    // get memory layout of template memory region
    map_entry* map_entry_list = get_map_entry_list(cid);
    cvm_map_entry_list[cid] = map_entry_list;

    // save memory memory content
    int fd = memfd_create(cvms[cid].libos, 0);
    cvm_snapshot_fd[cid] = fd;

    unsigned long long file_offset = 0;
    map_entry *p=map_entry_list;
    while(p) {
        size_t size = p->end - p->start;
        void* res =mmap(p->start, size, p->prot, MAP_SHARED|MAP_FIXED, fd, file_offset);
        assert(res != MAP_FAILED);

        file_offset += size;
        p = p->next;
    }
#endif

    // printf("save status = %d\n", status);
    if (status)
    {
        return;
    }
    // __asm__ __volatile__("sd sp, %0" :"=m" (cur_sp) :: "memory");
    printf("sp is %x; ra is %x; pc is %x\n", cur_sp, cur_ra, cur_pc);
    cvm_ctx[cid].pc = cur_pc + 4;
    cvm_ctx[cid].sp = cur_sp;
    cvm_ctx[cid].ra = cur_ra;
    cvm_ctx[cid].s0 = cur_s0;
    destroy_carrie_thread(threads);
}

void gen_caps_restored(struct s_box *cvm, struct cvm_tmplt_ctx *ctx, struct s_box *t_cvm) {
    void *prev_s0 = (void *)(*(unsigned long long *)(ctx->s0 - 16) + 112);
    void *__capability *caps = prev_s0 - 3*sizeof(void *__capability);
    
    void *ret_comp_pc = cheri_getoffset(caps[2]);
    printf("ret_from_mon's address is 0x%x\n", ret_comp_pc);
    void *__capability ret_comp_pcc = codecap_create(cvm->cmp_begin, cvm->cmp_end);
    ret_comp_pcc = cheri_setaddress(ret_comp_pcc, comp_to_mon((unsigned long long)ret_comp_pc, cvm));

    void * __capability ret_comp_dcap = datacap_create((void *) cvm->cmp_begin, (void *) cvm->cmp_end);
	
    void *__capability sealcap;
    size_t sealcap_size = sizeof(sealcap);
    if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0)
    {
        printf("sysctlbyname(security.cheri.sealcap)\n");
        while (1)
            ;
    }
    void *__capability *local_cap_store = comp_to_mon(0xe001000, cvm);
    void *__capability *comp_ddc = ((unsigned long long)local_cap_store) + 2 * sealcap_size;
    void *__capability *sealed_pcc = ((unsigned long long)local_cap_store) + 11 * sealcap_size;
    void *__capability *sealed_ddc = ((unsigned long long)local_cap_store) + 12 * sealcap_size;
    *sealed_pcc = cheri_seal(ret_comp_pcc, sealcap);
    *sealed_ddc = cheri_seal(ret_comp_dcap, sealcap);
    *comp_ddc = datacap_create((void *) cvm->cmp_begin, (void *) cvm->cmp_end);
    prev_s0 = mon_to_comp(prev_s0, t_cvm);

    __asm__ __volatile__ (
        "ld sp, %0;"
        "lc ct0, %1;"
        "lc ct1, %2;"
        "lc ct2, %3;"
        "cspecialw ddc, ct2;"
        "CInvoke ct0, ct1;" :: "m"(prev_s0), "m"(*sealed_pcc), "m"(*sealed_ddc), "m"(*comp_ddc)
    );
}

void load(int cid)
{
    struct c_thread *me = &cvms[cid].threads[0];
    int t_cid = me->sbox->t_cid;
    struct c_thread *t_me = &cvms[t_cid].threads[0];
    struct cvm_tmplt_ctx ctx = cvm_ctx[t_cid];
    gen_caps_restored(me->sbox, &ctx, t_me->sbox);
}