#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include <tfork.h>
#include "../monitor.h"

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
    asm(""
        : "=r"(cur_sp), "=r"(cur_ra));
    __asm__ __volatile__("auipc %0, 0"
                         : "=r"(cur_pc));
    // printf("save status = %d\n", status);
    if (status)
    {
        return;
    }
    status = 1;
    // __asm__ __volatile__("sd sp, %0" :"=m" (cur_sp) :: "memory");
    printf("sp is %x; ra is %x; pc is %x\n", cur_sp, cur_ra, cur_pc);
    cvm_ctx[cid].pc = cur_pc + 4;
    cvm_ctx[cid].sp = cur_sp;
    cvm_ctx[cid].ra = cur_ra;
    // cvm_ctx[cid].c_tp = threads[0].c_tp;
    destroy_carrie_thread(threads);
}

void load(int cid)
{
    struct c_thread *me = &cvms[cid].threads[0];
    int t_cid = me->sbox->t_cid;
    struct c_thread *t_me = &cvms[t_cid].threads[0];
    struct cvm_tmplt_ctx ctx = cvm_ctx[t_cid];
    // void *sp = comp_to_mon(ctx.sp, t_me->sbox);
    void *sp = (unsigned long long)ctx.sp % 0x10000000 + 0x10000000 * t_cid;
    void *ra = ctx.ra;
    printf("load: cid=%d, sp=%x, target_pc=%x\n", cid, sp, (void *)save + 2);
    void *__capability pcc_cap = cheri_getpcc();
    void *__capability ddc_cap = cheri_getdefault();
    pcc_cap = cheri_setaddress(pcc_cap, (void *)save + 2);
    void *__capability sealcap;
    size_t sealcap_size;

    sealcap_size = sizeof(sealcap);
    if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0)
    {
        printf("sysctlbyname(security.cheri.sealcap)\n");
        while (1)
            ;
    }
    void *__capability sealed_pcc = cheri_seal(pcc_cap, sealcap); // tp_write
    void *__capability sealed_ddc = cheri_seal(ddc_cap, sealcap); // default (?)
    __asm__ __volatile__(
        "mv sp, %0;"
        "mv tp, %1;"
        "mv ra, %6;"
        "li a0, 1;"
        "mv a1, %2;"
        "mv a2, %3;"
        "lc	cs3, %4;"
        "lc	cs4, %5;"
        "CInvoke cs3, cs4;" ::"r"(sp),
        "r"(me->c_tp), "r"(cid), "r"(me), "m"(sealed_pcc), "m"(sealed_ddc), "r"(ra)
        : "sp", "tp", "a0", "a1", "a2", "cs3", "cs4");
}