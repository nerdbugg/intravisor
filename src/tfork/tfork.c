#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include "../monitor.h"

#define RET_COMP_PPC (16 * 11)
#define RET_COMP_DDC (16 * 12)

const int TFORK_FAILED = MAP_FAILED;
const static int tfork_syscall_num = 577;

// struct cvm_tmplt_ctx cvm_ctx[MAX_CVMS];

int tfork(void *src_addr, void *dst_addr, int len)
{
    return syscall(tfork_syscall_num, src_addr, dst_addr, len);
}

void save_cur_thread_and_exit(int cid, struct c_thread *cur_thread)
{
    register void *cur_sp asm("sp");
    register void *cur_ra asm("ra");
    register void *cur_s0 asm("s0");
    asm(""
        : "=r"(cur_sp), "=r"(cur_ra), "=r"(cur_s0));

    // printf("save status = %d\n", status);
    // __asm__ __volatile__("sd sp, %0" :"=m" (cur_sp) :: "memory");
    printf("sp is %x; ra is %x;\n", cur_sp, cur_ra);
    cur_thread->ctx.sp = cur_sp;
    cur_thread->ctx.ra = cur_ra;
    cur_thread->ctx.s0 = cur_s0;
    destroy_carrie_thread(cur_thread->sbox->threads);
}

void gen_caps_restored(struct c_thread *target_thread)
{
    target_thread->m_tp = getTP();
    target_thread->c_tp = (void *)(target_thread->stack + 4096);
    
    struct s_box *cvm = target_thread->sbox;
    struct cvm_tmplt_ctx *ctx = &target_thread->ctx;
    struct s_box *t_cvm = &cvms[cvm->t_cid];

    void *prev_s0 = (void *)(*(uint64_t *)(ctx->s0 - 16) + 112);
    void *__capability *caps = prev_s0 - 3 * sizeof(void *__capability);

    void *ret_comp_pc = cheri_getoffset(caps[2]);
    printf("thread[tid=%x], ret_from_mon's address is 0x%x\n", target_thread->tid, ret_comp_pc);
    void *__capability ret_comp_pcc = codecap_create(cvm->cmp_begin, cvm->cmp_end);
    ret_comp_pcc = cheri_setaddress(ret_comp_pcc, comp_to_mon((unsigned long long)ret_comp_pc, cvm));

    void *__capability ret_comp_dcap = datacap_create((void *)cvm->cmp_begin, (void *)cvm->cmp_end);

    void *__capability sealcap;
    size_t sealcap_size = sizeof(sealcap);
    if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0)
    {
        printf("sysctlbyname(security.cheri.sealcap)\n");
        while (1)
            ;
    }
    void *__capability *local_cap_store = comp_to_mon(0xe001000, cvm);
    void *__capability *comp_ddc = ((uint64_t)local_cap_store) + 2 * sealcap_size;
    void *__capability *sealed_pcc = ((uint64_t)local_cap_store) + 11 * sealcap_size;
    void *__capability *sealed_ddc = ((uint64_t)local_cap_store) + 12 * sealcap_size;
    *sealed_pcc = cheri_seal(ret_comp_pcc, sealcap);
    *sealed_ddc = cheri_seal(ret_comp_dcap, sealcap);
    *comp_ddc = datacap_create((void *)cvm->cmp_begin, (void *)cvm->cmp_end);
    prev_s0 = mon_to_comp(prev_s0, t_cvm);

    __asm__ __volatile__(
        "ld sp, %0;"
        "lc ct0, %1;"
        "lc ct1, %2;"
        "lc ct2, %3;"
        "cspecialw ddc, ct2;"
        "CInvoke ct0, ct1;" ::"m"(prev_s0),
        "m"(*sealed_pcc), "m"(*sealed_ddc), "m"(*comp_ddc));
}

long load_sub_thread(struct c_thread *ct, struct c_thread *t_ct)
{
    int ret = pthread_attr_init(&ct->tattr);
    if (ret != 0)
    {
        perror("attr init");
        printf("ret = %d\n", ret);
        while (1)
            ;
    }

    ret = pthread_attr_setstack(&ct->tattr, ct->stack, ct->stack_size);
    if (ret != 0)
    {
        perror("pthread attr setstack");
        printf("ret = %d\n", ret);
    }

#ifdef __linux__
    ret = pthread_attr_setaffinity_np(&ct->tattr, sizeof(ct->sbox->cpuset), &ct->sbox->cpuset);
    if (ret != 0)
    {
        perror("pthread set affinity");
        printf("ret = %d\n", ret);
    }
#endif

    ret = pthread_create(&ct->tid, &ct->tattr, gen_caps_restored, ct);
    if (ret != 0)
    {
        perror("pthread create");
        printf("ret = %d\n", ret);
        while (1)
            ;
    }

    return (long)ct->tid;
}

void load_all_thread(int cid)
{
    struct s_box *cvm = &cvms[cid];
    struct c_thread *me = cvm->threads;
    int t_cid = me->sbox->t_cid;
    struct c_thread *t_me = cvms[t_cid].threads;

    for (int i = 1; i < 63; i++)
    {
        if (t_me[i].ctx.sp == NULL)
        {
            continue;
        }
        memcpy(&me[i], &t_me[i], sizeof(struct c_thread));
        me[i].sbox = cvm;
        printf("derived cvm has sub-thread, i=%d\n", i);
        load_sub_thread(&me[i], &t_me[i]);
    }

    gen_caps_restored(me);
}