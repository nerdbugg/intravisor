#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ucontext.h>

#include "monitor.h"
#include "tfork.h"
#include "cvm/log.h"
#include "assert.h"

#define SIGSAVE SIGUSR1
#define RET_COMP_PPC (16 * 11)
#define RET_COMP_DDC (16 * 12)

const int TFORK_FAILED = MAP_FAILED;
const static int tfork_syscall_num = 577;
extern struct c_thread *get_cur_thread();

map_entry* cvm_map_entry_list[MAX_CVMS];
int cvm_snapshot_fd[MAX_CVMS];

int tfork(void *src_addr, void *dst_addr, int len)
{
    return syscall(tfork_syscall_num, src_addr, dst_addr, len);
}

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

void save_cur_thread_and_exit(int cid, struct c_thread *cur_thread)
{
    register void *cur_sp asm("sp");
    register void *cur_ra asm("ra");
    register void *cur_s0 asm("s0");
    asm(""
        : "=r"(cur_sp), "=r"(cur_ra), "=r"(cur_s0));

#ifndef TFORK
    // get memory layout of template memory region
    map_entry* map_entry_list = get_map_entry_list(cid);
    cvm_map_entry_list[cid] = map_entry_list;

    //print_map_entry_list(map_entry_list);

    // save memory memory content
    int fd = memfd_create(cvms[cid].libos, 0);
    // change file size according to cmp size
    unsigned long cmp_begin = cvms[cid].cmp_begin;
    unsigned long cmp_end = cvms[cid].cmp_end;
    size_t cmp_size = cmp_end - cmp_begin;
    // set the memfd size
    ftruncate(fd, cmp_size);
    cvm_snapshot_fd[cid] = fd;

    // create mmap shared region
    void* res = mmap(NULL, cmp_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    assert(res != MAP_FAILED);

    dlog("cmp_begin = 0x%lx, cmp_end = 0x%lx\n", cmp_begin, cmp_end);
    dlog("snapshot data memory region: %p - %p\n", res, res+cmp_size);

    uint8_t* snapshot_data = res;
    unsigned long offset = 0;
    map_entry *p=map_entry_list;
    while(p!=NULL) {
        size_t size = p->end - p->start;

        memcpy(snapshot_data+offset, p->start, size);
        
        offset += size;
        p = p->next;
    }
    assert(munmap(snapshot_data, cmp_size)==0);
#endif
    // printf("save status = %d\n", status);
    // __asm__ __volatile__("sd sp, %0" :"=m" (cur_sp) :: "memory");

    dlog("sp is %x; ra is %x;\n", cur_sp, cur_ra);

    cur_thread->ctx.sp = cur_sp;
    // cur_thread->ctx.ra = cur_ra;
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

    dlog("gen_caps_restored: sealed_pcc \n");
    CHERI_CAP_PRINT(*sealed_pcc);
    dlog("gen_caps_restored: sealed_ddc \n");
    CHERI_CAP_PRINT(*sealed_ddc);
    dlog("gen_caps_restored: comp_ddc \n");
    CHERI_CAP_PRINT(*comp_ddc);

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

void notify_other_thread_save(struct c_thread *cur_thread)
{
    struct c_thread *threads = cur_thread->sbox->threads;
    assert(cur_thread == threads);
    for (int i = 1; i < 62; ++i)
    {
        if (threads[i].tid == NULL)
        {
            break;
        }
        // pthread_kill(threads[i].tid, SIGSAVE);
        threads[i].notified = true;
    }
}

// void save_sig_handler(int j, siginfo_t *si, ucontext_t *uap)
// {
//     printf("trap %d\n", j);
//     printf("SI_ADDR: %ld\n", si->si_addr);
    
//     struct c_thread *cur_thread = get_cur_thread();
//     mcontext_t *mctx = &((ucontext_t *)uap)->uc_mcontext;

    
// }

// void setup_save_sig()
// {
//     struct sigaction sa;
//     sa.sa_sigaction = save_sig_handler;
//     sigemptyset(&sa.sa_mask);
//     sa.sa_flags = SA_SIGINFO;

//     if (sigaction(SIGSAVE, &sa, NULL) == -1)
//     {
//         perror("sigaction");
//         exit(1);
//     }
// }