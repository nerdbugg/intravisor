#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ucontext.h>
#include <machine/ucontext.h>
#include <machine/reg.h>

#include "common/list.h"
#include "monitor.h"
#include "tfork.h"
#include "daemon.h"
#include "common/log.h"
#include "common/profiler.h"
#include "hostcalls/carrier_thread.h"
#include "hostcalls/host_syscall_callbacs.h"

#include "image/image.pb-c.h"

#define SIGSAVE SIGUSR1
#define RET_COMP_PPC (16 * 11)
#define RET_COMP_DDC (16 * 12)

const unsigned long TFORK_FAILED = (unsigned long)MAP_FAILED;
const static int tfork_syscall_num = 577;

int cvm_snapshot_fd[MAX_CVMS];


typedef void* __capability cap;

int tfork(void *src_addr, void *dst_addr, int len)
{
    return syscall(tfork_syscall_num, src_addr, dst_addr, len);
}

unsigned int parse_permstr(const char *perms)
{
    unsigned int res = 0;
    if (perms[0] == 'r')
        res |= PROT_READ;
    if (perms[1] == 'w')
        res |= PROT_WRITE;
    if (perms[2] == 'x')
        res |= PROT_EXEC;
    return res;
}

void vm_map_entry_list_init(vm_map_entry_list* vm_map_entries) {
  memset(vm_map_entries, 0, sizeof(struct vm_map_entry_list));
  INIT_LIST_HEAD(&(vm_map_entries->h));
}

vm_map_entry_list *get_vm_map_entry_list(int cid)
{
    FILE *map_file = fopen("/proc/curproc/map", "r");
    assert(map_file != NULL);

    vm_map_entry_list *vm_map_entries = malloc(sizeof(vm_map_entry_list));
    vm_map_entry_list_init(vm_map_entries);

    unsigned long range_low, range_high;
    range_low = cvms[cid].cmp_begin;
    range_high = cvms[cid].cmp_end;

    unsigned long start, end;
    int resident, privateresident;
    void *obj;
    char permstr[32] = "";

    char map_buf[256];
    while (fgets(map_buf, sizeof(map_buf), map_file))
    {
        int num = sscanf(map_buf, "0x%lx 0x%lx %d %d %p %31s",
                         &start, &end,
                         &resident, &privateresident,
                         &obj, permstr);
        assert(num == 6);

        if (end - 1 < range_low)
            continue;
        if (start >= range_high)
            break;

        int prot = parse_permstr(permstr);

        vm_map_entry *entry = (vm_map_entry*)malloc(sizeof(vm_map_entry));
        vma_entry__init(&(entry->e));

        entry->e.start = start;
        entry->e.end = end;
        entry->e.prot = prot;
        entry->e.flags = 0;

        list_add_tail(&(entry->list), &(vm_map_entries->h));
        vm_map_entries->nr++;
    }
    fclose(map_file);

    return vm_map_entries;
}

int collect_fds(Image *image, struct s_box *cvm) {
  // TODO: empty impl here
  Fdinfo *fdinfo = malloc(sizeof(Fdinfo));
  fdinfo__init(fdinfo);

  fdinfo->n_fdinfo_entries = 0;

  image->fileinfo = fdinfo;

  return 0;
}

int collect_map_entries(Image *image, vm_map_entry_list *vm_map_entries) {
  MmStruct *mm_struct = malloc(sizeof(MmStruct));
  mm_struct__init(mm_struct);

  mm_struct->vma_entries = malloc(sizeof(VmaEntry)*vm_map_entries->nr);

  uint64_t pgoff=0l;
  vm_map_entry *entry;
  list_for_each_entry(entry, &(vm_map_entries->h), list) {
    VmaEntry *e = &(entry->e);
    e->pgoff = pgoff;

    size_t region_size = e->end - e->start;
    pgoff += region_size;
    mm_struct->vma_entries[mm_struct->n_vma_entries++] = e;
    mm_struct->size += region_size;
  }

  vm_map_entry *first_entry = list_first_entry(&(vm_map_entries->h), struct vm_map_entry, list);
  mm_struct->start = first_entry->e.start;

  image->meminfo = mm_struct;
  return 0;
}

int serialize_image(char* snapshot_path, Image *image) {
  char image_path[128];
  sprintf(image_path, "%s/image.img", snapshot_path);

  dlog("[debug/dump] fopen(%s, \"wb+\")\n", image_path);
  FILE *image_file = fopen(image_path, "wb+");
  if(image_file==NULL) {
    printf("Snapshot image open error.\n");
    exit(1);
  }

  size_t buf_len = image__get_packed_size(image);
  uint8_t *buf = malloc(buf_len);
  int res = image__pack(image, buf);

  for(size_t l=0l;l<buf_len;l+=fwrite(buf, sizeof(uint8_t), buf_len, image_file));
  
  fclose(image_file);
  return 0;
}

void destroy_local_cap_store(int cid) {
  struct s_box *cvm = &(cvms[cid]);
  void* local_cap_store = cvm->base+0xe001000;
  size_t local_cap_store_size = sizeof(void*__capability) * 13;
  printf("[debug/dump] destroy caps in %p - %p\n", local_cap_store, local_cap_store+local_cap_store_size);
  printf("[debug/dump] sizeof(void*__capability) = %ld\n", sizeof(void*__capability));
  printf("[debug/dump] sizeof local_cap_store = %ld\n", local_cap_store_size);

  // do not work, still sicode=103 during copying
  memset(local_cap_store, 0, local_cap_store_size);
}

void save_cur_thread_and_exit(int cid, struct c_thread *cur_thread)
{
    register void *cur_sp asm("sp");
    register void *cur_ra asm("ra");
    register void *cur_s0 asm("s0");
    asm(""
        : "=r"(cur_sp), "=r"(cur_ra), "=r"(cur_s0));

#ifndef TFORK
    Image *image = malloc(sizeof(Image));
    image__init(image);

    // get memory layout of template memory region
    vm_map_entry_list *vm_map_entries = get_vm_map_entry_list(cid);

    collect_map_entries(image, vm_map_entries);

    collect_fds(image, &(cvms[cid]));

    serialize_image(cvms[cid].snapshot_path, image);

    char name_buf[128];
    sprintf(name_buf, "%s/pages.img", cvms[cid].snapshot_path);

    // TODO: delete this
    destroy_local_cap_store(cid);

    // NOTE: save memory memory content of template here
    // capability should destroied before this
    FILE *page_file = fopen(name_buf, "wb+");
    if(page_file==NULL) {
        printf("[debug/dump] page file open failed.");
        exit(1);
    }
    int page_fd = fileno(page_file);
    size_t page_file_size = image->meminfo->size;

    unsigned long offset = 0;

    vm_map_entry *entry;
    list_for_each_entry(entry, &(vm_map_entries->h), list) {
      size_t region_size = entry->e.end - entry->e.start;

      size_t res = fwrite((void*)entry->e.start, sizeof(uint8_t), region_size, page_file);
      assert(res == region_size);

      dlog("[debug/dump] entry->start = 0x%lx, offset = 0x%lx, writed size: 0x%lx\n", 
           entry->e.start, offset, res);
      dlog("[debug/dump] writed size: 0x%lx, expected: 0x%lx\n", res, region_size);

      offset += region_size;
    }

    fclose(page_file);
#endif
    // printf("save status = %d\n", status);
    // __asm__ __volatile__("sd sp, %0" :"=m" (cur_sp) :: "memory");

    log("s0 is %p, sp is %p, ra is %p,\n", cur_s0, cur_sp, cur_ra);

    // cur_thread->ctx.s0 = cur_sp;
    // cur_thread->ctx.ra = cur_ra;
    cur_thread->ctx.s0 = cur_s0;

    profiler_end(&(profilers[SNAPSHOT_GEN]));

    destroy_carrie_thread(cur_thread->sbox->threads);
}

// note: restore main thread of cvm (from half of tp_write function)
void restore_main_thread(struct c_thread *target_thread)
{
    target_thread->m_tp = getTP();
    target_thread->c_tp = (void *)(target_thread->stack + 4096);

    struct s_box *cvm = target_thread->sbox;
    struct cvm_tmplt_ctx *ctx = &target_thread->ctx;
    struct s_box *t_cvm = &cvms[cvm->t_cid];

    void *ret_comp_pc = (void*)cvm->ret_from_mon;
    void *__capability ret_comp_pcc = codecap_create((void*)cvm->cmp_begin, (void*)cvm->cmp_end);
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

    // note: write caps to local_cap_store region
    // void *__capability *local_cap_store = comp_to_mon(0xe001000, cvm);
    // void *__capability *comp_ddc = ((uint64_t)local_cap_store) + 2 * sealcap_size;
    // void *__capability *sealed_pcc = ((uint64_t)local_cap_store) + 11 * sealcap_size;
    // void *__capability *sealed_ddc = ((uint64_t)local_cap_store) + 12 * sealcap_size;
    // *sealed_pcc = cheri_seal(ret_comp_pcc, sealcap);
    // *sealed_ddc = cheri_seal(ret_comp_dcap, sealcap);
    // *comp_ddc = datacap_create((void *)cvm->cmp_begin, (void *)cvm->cmp_end);
 
    void *local_cap_store = (void*)comp_to_mon(0xe001000, cvm);
    void *comp_ddc = (void*)((uint64_t)local_cap_store) + 2 * sealcap_size;
    void *sealed_pcc = (void*)((uint64_t)local_cap_store) + 11 * sealcap_size;
    void *sealed_ddc = (void*)((uint64_t)local_cap_store) + 12 * sealcap_size;
    void *sealed_hc_pcc = (void*)((uint64_t)local_cap_store) + 3 * sealcap_size;
    void *sealed_mon_ddc = (void*)((uint64_t)local_cap_store) + 4 * sealcap_size;

    st_cap(sealed_pcc, cheri_seal(ret_comp_pcc, sealcap));
    st_cap(sealed_ddc, cheri_seal(ret_comp_dcap, sealcap));
    st_cap(comp_ddc, datacap_create((void *)cvm->cmp_begin, (void *)cvm->cmp_end));

    if (target_thread->cb_out == NULL) {
      dlog("callback_out is empty, use default 'monitor'\n");
      target_thread->cb_out = "monitor";
    }
    // ignore sealed_hc_pcc2 here
    host_syscall_handler_prb(target_thread->cb_out, &target_thread->sbox->box_caps.sealed_hc_pcc,
                             &target_thread->sbox->box_caps.sealed_mon_ddc,
                            &target_thread->sbox->box_caps.sealed_hc_pcc2);

    st_cap(sealed_mon_ddc, target_thread->sbox->box_caps.sealed_mon_ddc);
    st_cap(sealed_hc_pcc, target_thread->sbox->box_caps.sealed_hc_pcc);

    dlog("gen_caps_restored: sealed_pcc \n");
    CHERI_CAP_PRINT(*(cap*)sealed_pcc);
    dlog("gen_caps_restored: sealed_ddc \n");
    CHERI_CAP_PRINT(*(cap*)sealed_ddc);
    dlog("gen_caps_restored: comp_ddc \n");
    CHERI_CAP_PRINT(*(cap*)comp_ddc);

    profiler_end(&(profilers[SANDBOX_RESUME]));
    profiler_begin(&(profilers[WORKLOAD_RESUME]));

    // TODO: get a reliable source of prev sp register
    void *prev_s0 = (void *)(*(uint64_t *)(ctx->s0 - 16) + 112);
    // note: initialize the sp
    void *sp = (void*)mon_to_comp((unsigned long)prev_s0, t_cvm);

    // note: restore sp register and cinvoke to the ret_from_monitor
    __asm__ __volatile__(
        "ld sp, %0;"
        "lc ct0, %1;"
        "lc ct1, %2;"
        "lc ct2, %3;"
        "cspecialw ddc, ct2;"
        "CInvoke ct0, ct1;" ::"m"(sp),
        "m"(*(cap*)sealed_pcc), "m"(*(cap*)sealed_ddc), "m"(*(cap*)comp_ddc));
}

// note: start a new thread from template ucontext
int load_ucontext(struct c_thread *target_thread)
{
    ucontext_t uctx;
    struct s_box *cvm, *t_cvm;
    struct capregs mc_capregs; // ucontext cap_regs
    size_t sealcap_size;

    cvm = target_thread->sbox;
    t_cvm = &cvms[cvm->t_cid];

    target_thread->m_tp = getTP();
    target_thread->c_tp = (void *)(target_thread->stack + 4096);

    memset(&uctx, 0, sizeof(uctx));
    memset(&mc_capregs, 0, sizeof(mc_capregs));
    // use gp_regs and cp_regs to initialize uctx.uc_mcontext ;
    memcpy(&(uctx.uc_mcontext.mc_gpregs), &(target_thread->gp_regs), sizeof(struct reg));
    memcpy(&mc_capregs, &(target_thread->cap_regs), sizeof(struct capreg));
    mc_capregs.cp_sstatus = target_thread->gp_regs.sstatus;

    void* __capability ddc=(void* __capability)target_thread->cap_regs.ddc;
    unsigned long base = cheri_getbase(ddc);
    if (base==0x0) { // monitor
        // change tp (gpregs, capregs)
        uctx.uc_mcontext.mc_gpregs.gp_tp = (uintptr_t)target_thread->m_tp;
        mc_capregs.cp_ctp = (uintptr_t)target_thread->m_tp;
        // change sp (gpregs, capregs)
        void* sp = (void*)uctx.uc_mcontext.mc_gpregs.gp_sp;
        sp = sp - t_cvm->base + cvm->base;
        uctx.uc_mcontext.mc_gpregs.gp_sp = (uintptr_t)sp;
        mc_capregs.cp_csp = (uintptr_t)sp;

        uctx.uc_mcontext.mc_capregs = (uintptr_t)&mc_capregs;
        uctx.uc_mcontext.mc_flags = 0x0;
    } else { // compartment
        // change tp (gpregs, capregs)
        uctx.uc_mcontext.mc_gpregs.gp_tp = (uintptr_t)target_thread->c_tp;
        mc_capregs.cp_ctp = (uintptr_t)target_thread->c_tp;
        // change sepc (gpregs)
        register_t sepc = uctx.uc_mcontext.mc_gpregs.gp_sepc; // absolute
        sepc = sepc - t_cvm->cmp_begin; // cap-relative
        uctx.uc_mcontext.mc_gpregs.gp_sepc = sepc;
        // change sepcc (capregs)
        // cooperate with sepc, the final sepcc = cheri_setoffset(cp_sepcc, sepc)
        void *__capability cp_sepcc = codecap_create((void*)cvm->cmp_begin, (void*)cvm->cmp_end);
        // change ddc (capregs)
        void *__capability cp_ddc = datacap_create((void*)cvm->cmp_begin, (void *)cvm->cmp_end);
        mc_capregs.cp_sepcc = (uintptr_t)cp_sepcc;
        mc_capregs.cp_ddc = (uintptr_t)cp_ddc;

        // note: set mc_capregs and set flag
        uctx.uc_mcontext.mc_capregs = (uintptr_t)&mc_capregs;
        // note: would use mc_capregs(add sepc) to set new context
        uctx.uc_mcontext.mc_flags = _MC_CAP_VALID;
    }

    dlog("monitor: load_ucontext, &ucontext=%p, &mc_capregs=%p\n", &uctx, &mc_capregs);
    dlog("sizeof(uctx)=%lu, sizeof(mc_capregs)=%lu\n", sizeof(ucontext_t), sizeof(struct capregs));
    dlog("monitor: load_ucontext, sepc=%p, pcc.base=0x%lx\n", 
         (void*)uctx.uc_mcontext.mc_gpregs.gp_sepc, 
         cheri_getbase((void* __capability)mc_capregs.cp_sepcc));
    dlog("monitor: load_ucontext, sp=%p, ddc.base=0x%lx\n", 
         (void*)uctx.uc_mcontext.mc_gpregs.gp_sp, 
         cheri_getbase((void* __capability)mc_capregs.cp_ddc));

    // pthread function
    return setcontext(&uctx);
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

    void* res=mmap(NULL, TEMP_STACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    assert(res!=MAP_FAILED);
    ct->temp_stack = res;
    ret = pthread_attr_setstack(&ct->tattr, ct->temp_stack, TEMP_STACK_SIZE);
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
    ret = pthread_create(&ct->tid, &ct->tattr, load_ucontext, ct);
    if (ret != 0)
    {
        perror("pthread create");
        printf("ret = %d\n", ret);
        while (1)
            ;
    }

    return (long)ct->tid;
}

void restore_from_template(int cid)
{
    struct s_box *cvm = &cvms[cid];
    struct c_thread *me = cvm->threads;
    int t_cid = me->sbox->t_cid;
    struct c_thread *t_me = cvms[t_cid].threads;

    // note: initialize all sub-threads
    for (int i = 1; i < MAX_THREADS; i++) {
        // note:global is initalize as zero
        if (t_me[i].gp_regs.sp == (uint64_t)NULL) {
            break;
        }
        dlog("monitor: load_all_thread, t_me[%d]\n", i);

        // todo: copy again? repeated?
        memcpy(&me[i], &t_me[i], sizeof(struct c_thread));
        me[i].sbox = cvm;
        // change stack base addr
        me[i].stack = t_me[i].stack - t_me->sbox->base + cvm->base;
        // change func
        me[i].func = t_me[i].func - t_me->sbox->base + cvm->base;
        dlog("derived cvm has sub-thread, i=%d\n", i);
        load_sub_thread(&me[i], &t_me[i]);
    }

    // note: the main thread(who called host_save) will restored in below path
    // note: restore main thread of cvm
    restore_main_thread(me);
}

// note: cur hostcall use, request daemon for threads state
void notify_other_thread_save(struct c_thread *cur_thread)
{
    int i, capreg_size;
    void *sp;
    extern int send_req, receive_resp;
    struct c_thread *threads;
    snapshot_req_t req;
    snapshot_resp_t resp;

    ucontext_t uctx;
    struct capregs *stack_capregs;

    threads = cur_thread->sbox->threads;
    assert(cur_thread == threads);

    memset(&req, 0, sizeof(req));
    req.main_thread_id = (pthread_t)threads[0].task_id;
    req.host_exit_addr = (unsigned long)cur_thread->sbox->base + cur_thread->sbox->host_exit_addr;
    dlog("monitor: main_thread_id=%lu\n", (unsigned long)req.main_thread_id);
    for (i = 1; i < 62; ++i) {
        if (threads[i].task_id == NULL)
        {
            break;
        }
        dlog("monitor: threads[%d].tid=%ld\n", i, threads[i].task_id);
        req.sub_threads[i - 1].task_id = threads[i].task_id;
        req.sub_threads[i - 1].pthread_id = threads[i].tid;
        req.sub_threads[i - 1].ct = &(threads[i]);
    }
    if (i == 1) {
        return;
    }

    dlog("monitor: ready to send snapshot req. fd=%d\n", send_req);
    write(send_req, &req, sizeof(req));

    dlog("monitor: ready to read snapshot response. fd=%d\n", receive_resp);
    read(receive_resp, &resp, sizeof(resp));
    dlog("monitor: receive snapshot response.\n");

    // save ptrace result
    for (i = 0; i < MAX_THREADS; i++) {
        // note: save sub threads' state
        sp = (void*)resp.contexts[i].gp_regs.sp;
        if (sp == NULL) {
            break;
        }

        threads[i+1].gp_regs = resp.contexts[i].gp_regs;
        threads[i+1].cap_regs = resp.contexts[i].cap_regs;
    };
    dlog("monitor: notify_other_thread_save finish.\n");
}

