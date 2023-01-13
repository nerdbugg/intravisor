#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include <tfork.h>
#include "../monitor.h"

#define RET_COMP_PPC (16*11)
#define RET_COMP_DDC (16*12)

const int TFORK_FAILED = MAP_FAILED;
const static int tfork_syscall_num = 577;

struct cvm_tmplt_ctx cvm_ctx[MAX_CVMS];

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