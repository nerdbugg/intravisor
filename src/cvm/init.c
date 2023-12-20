#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/thr.h>

#include "common/log.h"
#include "common/profiler.h"
#include "common/utils.h"
#include "hostcalls/fs/fd.h"
#include "monitor.h"
#include "restore.h"
#include "template.h"

struct cinv_s {
  void *__capability caps[10];
};

typedef void *(thread_func)(void *);

void *run_cvm(int cid);
void *cvm_worker(void *arg);
int init_cvm(int cid, struct cmp_s *comp, char *libos, char *disk, int argc,
             char *argv[], char *cb_out, char *cb_in);
int init_cvm_caps(struct s_box *cvm, struct c_thread *ct);
void cinv(void *local_cap_store, struct cinv_s *args, void *sp);

struct s_box *build_from_config(struct cvm *f) {
  int cid = f->isol.base / CVM_MAX_SIZE;
  dlog("Deploy cthread of cvm, cid=%d\n", cid);

  struct s_box *cvm = &cvms[cid];
  struct c_thread *ct = cvm->threads;

  if (pthread_mutex_init(&cvm->ct_lock, NULL) != 0) {
    printf("\n mutex init failed\n");
    exit(1);
  }
  int ret;
  ret = pthread_attr_init(&ct->tattr);
  if (ret != 0) {
    perror("attr init");
    printf("ret = %d\n", ret);
    while (1)
      ;
  }

  cvm->cmp_begin = f->isol.begin;
  cvm->cmp_end = f->isol.end;
  cvm->box_size = f->isol.size;
  ct->stack_size = (MAX_THREADS + 1) * STACK_SIZE;
  ct->stack = (void *)(cvm->cmp_end - ct->stack_size);

  int t_cid = find_template(cid, f->runtime);
  cvm->t_cid = t_cid;

  cvm->fork = f->fork;

  cvm->is_template = f->template;

  cvm->resume = f->resume;
  cvm->resume = (cvm->t_cid > 0) && cvm->resume;

  cvm->snapshot_path = f->snapshot_path;
  return cvm;
}

void create_and_start_cvm(struct cvm *f) {
  struct s_box *cvm = build_from_config(f);
  struct c_thread *ct = cvm->threads;
  int ret;

  if (cvm->resume == false) {
    init_pthread_stack(cvm);
  } else {
    restore_cvm_region(cvm, &(cvms[cvm->t_cid]));
  }

  // TODO: maybe stack conflicts when exec load template.
  if (cvm->resume) {
    ret = pthread_attr_setstack(&ct->tattr, ct->stack, ct->stack_size);
  } else {
    ret = pthread_attr_setstack(&ct->tattr, ct->stack, ct->stack_size);
  }

  if (ret != 0) {
    perror("pthread attr setstack");
    dlog("ret = %d\n", ret);
    while (1)
      ;
  }

  ret = pthread_create(&ct->tid, &ct->tattr, cvm_worker, f);

  dlog("pthread_create ret = %d\n", ret);
  if (ret != 0) {
    perror("pthread_create");
    exit(1);
  }

  dlog("f->wait=%d\n", f->wait);

  if (f->wait == -1) {
    dlog("pthread join, tid=%p, isol.base=%p\n", ct->tid, (void *)f->isol.base);

    void *cret;
    for (int i = 0; true; i++) {
      if (ct[i].tid == NULL) {
        break;
      }
      pthread_join(ct[i].tid, &cret);

      dlog("cvm[%ld]-thread[%d] has exited.\n", cvm - cvms, i);
    }

    dlog("join returned\n");
  } else
    sleep(f->wait);
}

int build_cvm(struct cvm *f) {
  int cid = f->isol.base / 0x10000000;

  enum { kMaxArgs = 16 };
  int c_argc = 0;
  long *c_argv = malloc(kMaxArgs * sizeof(long));

  char *p2 = strtok(f->args, " ");
  while (p2 && c_argc < kMaxArgs - 1) {
    c_argv[c_argc++] = (long)p2;
    p2 = strtok(0, " ");
  }
  c_argv[c_argc] = 0;

  struct cmp_s comp;
  comp.base = (void *)f->isol.base; /* base addr */
  comp.size = f->isol.size;         /* size */
  comp.begin = f->isol.begin;       /* cmp_begin */
  comp.end = f->isol.end;           /* cmp_end  */

  int t_cid = cvms[cid].t_cid;
  if (cvms[cid].resume == false) {
    // todo: sanitise base addresses, check cvms/sbox max number
    // so far it is the best I can offer.
    init_cvm(cid, &comp, f->runtime, f->disk, c_argc, (char **)c_argv,
             f->cb_out, f->cb_in);
  } else {
    if(cvms[cid].fork) {
      fork_cvm(cid, t_cid, &comp, c_argc, (char **)c_argv);
    } else {
      // FIXME: complete true restore logic, resote completely from image
      fork_cvm(cid, t_cid, &comp, c_argc, (char **)c_argv);
      // restore_cvm_from_image(cid, t_cid, &comp, c_argc, (char**)c_argv, f->snapshot_path);
    }
  }
  // assert(cvms[cid].threads[0].sbox != 0);
  return cid;
}

void *cvm_worker(void *arg) {
  struct cvm *f = (struct cvm *)arg;
  dlog("***************** [%ld] Deploy '%s' ***************\n",
       f->isol.base / CVM_MAX_SIZE, f->name);
  dlog("BUILDING cvm: name=%s, disk=%s, runtime=%s, net=%s, args='%s', "
       "base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, cb_in = '%s', cb_out = "
       "'%s' wait = %ds, fork=%d, resume = %d, snapshot_path = %s\n",
       f->name, f->disk, f->runtime, f->net, f->args, f->isol.base,
       f->isol.size, f->isol.begin, f->isol.end, f->cb_in, f->cb_out, f->wait,
       f->fork, f->resume, f->snapshot_path);

  int cid = build_cvm(f);
  dlog("BUILDING cvm complete: cid=%d, disk=%s, runtime=%s, base=%p, "
       "size=0x%lx, begin=0x%lx, end=0x%lx, syscall_handler = '%ld', "
       "ret_from_mon = '0x%lx'\n",
       cid, cvms[cid].disk_image, cvms[cid].libos, cvms[cid].base,
       cvms[cid].box_size, cvms[cid].cmp_begin, cvms[cid].cmp_end,
       cvms[cid].syscall_handler, cvms[cid].ret_from_mon);

  struct s_box *cvm = &cvms[cid];
  if (cvm->resume == false) {
    // is template
    run_cvm(cid);
  } else {
    dlog("load template, cid=%d, t_cid=%d\n", cid, cvm->t_cid);
    restore_from_template(cid);
  }
  return NULL;
}

void init_cvm_thread(struct s_box *cvm, void *func, char *cb_in, char *cb_out,
                     int argc, char *argv[]) {
  struct c_thread *ct = cvm->threads;
  for (int i = 0; i < MAX_THREADS; i++) {
    ct[i].id = -1;
    ct[i].sbox = cvm;
  }

  ct[0].id = 0;
  ct[0].func = func;
  ct[0].cb_in = cb_in;
  ct[0].cb_out = cb_out;
  ct[0].stack_size = STACK_SIZE;
  ct[0].stack = (void *)((unsigned long)cvm->top - STACK_SIZE);
  ct[0].arg = NULL;
  ct[0].sbox = cvm;

  ct[0].argc = argc;
  ct[0].argv = argv;
}

int init_cvm_mem(int cid, char *libos) {
  struct s_box *cvm = &(cvms[cid]);
  struct encl_map_info encl_map;

  void *base = (void *)cvm->cmp_begin;
  unsigned long size = cvm->box_size;
  unsigned long cmp_begin = cvm->cmp_begin;
  unsigned long cmp_end = cvm->cmp_end;

  memset(&encl_map, 0, sizeof(struct encl_map_info));

  load_elf(libos, base, &encl_map);
  if (encl_map.base < 0) {
    printf("Could not load '%s', die\n", libos);
    while (1)
      ;
  }

  if (encl_map.base != base) {
    printf("mapped at wrong addres [%p]:[%p], die\n", encl_map.base, base);
    while (1)
      ;
  }

  if (encl_map.size > CVM_MAX_SIZE) {
    log("Actual cVM is bigger(0x%lx) than it could be(0x%x), die\n",
        encl_map.size, CVM_MAX_SIZE);
    while (1)
      ;
  }
  dlog("ELF BASE = %p, MAP SIZE = %lx, ENTRY = %p\n", encl_map.base,
       encl_map.size, encl_map.entry_point);

  int ret = 0;

  if (encl_map.entry_point == 0) {
    printf("entry_point is 0, runtime image is wrong/corrupted\n");
    while (1)
      ;
  } else {
    dlog("encl_map.entry = %p\n", encl_map.entry_point);
  }

  if (encl_map.ret_point == 0) {
    printf("ret_from_monitor is 0, runtime image is wrong/corrupted\n");
    while (1)
      ;
  } else {
    dlog("encl_map.ret = %p\n", (void *)encl_map.ret_point);
  }

  cvms[cid].host_exit_addr = (uint64_t)encl_map.host_exit;
  if (encl_map.cap_relocs) {
    printf("we have __cap_relocs, it is a purecap binary\n");
    cvms[cid].pure = 1;
    // cvms[cid].use_scl = 2; //todo, should be a list of SCL it uses
    cvms[cid].cr = (struct cap_relocs_s *)encl_map.cap_relocs;
    cvms[cid].cap_relocs_size = encl_map.cap_relocs_size;
    cvms[cid].cap_relocs = encl_map.cap_relocs;
    struct cap_relocs_s *cr = (struct cap_relocs_s *)encl_map.cap_relocs;
    for (int j = 0; j < encl_map.cap_relocs_size / sizeof(struct cap_relocs_s);
         j++) {
      dlog("Create cap: %p Base: %p Length: %ld Perms: %lx Unk = %ld\n",
           base + cr[j].dst, (void *)cr[j].addr, cr[j].len, cr[j].perms,
           cr[j].unknown);
      void *__capability rel_cap;
      if (cr[j].perms == 0x8000000000000000ll) { // Function
        // All caps are PCC-size. It is itended otherwise AUIPC doesn't work
        rel_cap = pure_codecap_create((void *)base, (void *)base + size);
        rel_cap = cheri_setaddress(rel_cap, base + cr[j].addr);
      } else if (cr[j].perms == 0x0ull) { // Object
        // TODO: we need something better
        if (cr[j].len ==
            0xabba) { // size of local_cap_store defined in elf file
          log("replace cap for caps\n");
          log("RISCV ABI\n");
          // redefine it in base+0xe001000 - base+0xe002000
          rel_cap = datacap_create((void *)base + 0xe001000, base + 0xe002000);
        } else
          rel_cap = datacap_create((void *)base + cr[j].addr,
                                   (void *)base + cr[j].addr + cr[j].len);
      } else if (cr[j].perms == 0x4000000000000000ll) { // Constant
        rel_cap = datacap_create((void *)base + cr[j].addr,
                                 (void *)base + cr[j].addr + cr[j].len);
      } else {
        log("Wrong Perm! 0x%lx, die\n", cr[j].perms);
        while (1)
          ;
      }

      CHERI_CAP_PRINT(rel_cap);
      st_cap((void *)(cr[j].dst + base), rel_cap);
    }
  }

  cvms[cid].base = encl_map.base;
  cvms[cid].top = (void *)((unsigned long)base + size);
  cvms[cid].box_size = encl_map.size;
  cvms[cid].entry = encl_map.entry_point;
  cvms[cid].stack_size =
      (MAX_THREADS + 1) * STACK_SIZE; // last thread -- store for caps

  cvms[cid].ret_from_mon = encl_map.ret_point;
  cvms[cid].syscall_handler = encl_map.syscall_handler;

  cvms[cid].end_of_ro = encl_map.end_of_ro;
  cvms[cid].extra_load = encl_map.extra_load;
  cvms[cid].cid = cid;

  // setup libos field
  memset(cvms[cid].libos, 0, MAX_LIBOS_PATH);
  strcpy(cvms[cid].libos, libos);

  cvms[cid].cmp_begin = cmp_begin;
  cvms[cid].cmp_end = cmp_end;

  return 0;
}

int init_cvm_fs(int cid, char *disk) {
  // init cvm fdtable
  fdtable_init(&(cvms[cid].fdtable));

#if 0
	cvms[cid].fd = create_console(cid);
#else
  cvms[cid].fd = STDOUT_FILENO;
#endif

  if (disk)
    strncpy(cvms[cid].disk_image, disk, sizeof(cvms[cid].disk_image));
}

int init_cvm(int cid, struct cmp_s *comp, char *libos, char *disk, int argc,
             char *argv[], char *cb_out, char *cb_in) {
  struct s_box *cvm = &(cvms[cid]);

  init_cvm_mem(cid, libos);

  init_cvm_fs(cid, disk);

  // cvm->entry is initialized in init_cvm_mem
  init_cvm_thread(&cvms[cid], cvm->entry, cb_in, cb_out, argc, argv);

  /*** gen caps ***/
  // do we really need to save the sealcap?
  init_cvm_caps(&cvms[cid], &(cvms[cid].threads[0]));
  return 0;
}

void *run_cvm(int cid) {
  struct c_thread *me = &cvms[cid].threads[0];
  thr_self(&me->task_id);
  // assert(me->sbox != 0);
  void *sp_read =
      me->stack +
      me->stack_size; // getSP(); = 0x2ff80000 + 524288 = 0x3000 0000 = cmp_end
  char argv1[128];
  char lc1[128];
  char env1[128];
  char env2[128];
  char env3[128];
  char env4[128];
  char env5[128];

  snprintf(argv1, 128, "/ld.so");
  snprintf(lc1, 128, "LC_ALL=C.UTF-8");

  snprintf(env1, 128, "PYTHONHOME=/usr");
  snprintf(env2, 128, "PYTHONPATH=/usr");
  snprintf(env3, 128, "PYTHONUSERBASE=site-packages");
  snprintf(env4, 128, "TMPDIR=/tmp");
  snprintf(env5, 128, "PYTHONDEBUG=3");
  //	snprintf(env5, 128, "_PYTHON_SYSCONFIGDATA_NAME=_sysconfigdata");

  me->m_tp = getTP();
  // NOTE: stack bottom 4KB reserved for tp
  me->c_tp = me->stack + 4096;

  // NOTE: stack top 3*4KB reserved for cenv, cvm_worker stack
  // stack top 4*4KB is the top of inner cvm sp
  char *cenv = (char *)(sp_read - 4096 * 3); // originally, here was *2, but
                                             // networking corrupts this memory
  volatile unsigned long *sp =
      (sp_read - 4096 * 4); // I don't know why, but without volatile sp gets
                            // some wrong value after initing CENV in -O2

  dlog("target SP = 0x%lx, old TP = %p sp_read = %p, me->stacl = %p, "
       "getSP()=%p, me->c_tp = %p\n",
       (unsigned long)sp, getTP(), sp_read, me->stack, getSP(), me->c_tp);

  int cenv_size = 0;
  // sp 是栈顶指针(位于低地址), 初始化栈按地址增长方向, 依次存放 argc, argv,
  // envs
  sp[0] = me->argc;
#ifdef HYB_CVM
  sp[1] = (unsigned long)(mon_to_comp(argv1, me->sbox));
#else
  sp[1] = 0xaa;
  sp[2] = (unsigned long)(mon_to_comp(argv1, me->sbox));
  sp[3] = 0xbb;
  int shift = 4;
#endif

  int i;
  for (i = 1; i < me->argc; i++) {
    printf("[%d] '%s'\n", i, me->argv[i]);

    int tmp_add = snprintf(&cenv[cenv_size], 128, "%s\0", me->argv[i]);
    if (cenv_size + tmp_add > 4096) {
      printf("need more space for args on the stack, die\n");
      while (1)
        ;
    }
#ifdef HYB_CVM
    sp[i + 1] = (unsigned long)(mon_to_comp(&cenv[cenv_size], me->sbox));
    printf("sp[i+1] = '%s'\n", (char *)(comp_to_mon(sp[i + 1], me->sbox)));
#else
    sp[shift + 2 * (i - 1)] =
        (unsigned long)(mon_to_comp(&cenv[cenv_size], me->sbox));
    sp[shift + 2 * (i - 1) + 1] = 0xcc + i - shift;
#endif
    cenv_size += tmp_add + 1;
  }
#ifdef HYB_CVM
  sp[i + 1] = 0; // terminator
  int ienv = i + 2;

  dlog("&env0 = %p, &env1=%p\n", &sp[ienv], &sp[ienv + 1]);

  sp[ienv++] = mon_to_comp(lc1, me->sbox);
  sp[ienv++] = mon_to_comp(env1, me->sbox);
  sp[ienv++] = mon_to_comp(env2, me->sbox);
  sp[ienv++] = mon_to_comp(env3, me->sbox);
  sp[ienv++] = mon_to_comp(env4, me->sbox);
  sp[ienv++] = mon_to_comp(env5, me->sbox);
  sp[ienv++] = 0;
#else
  sp[shift + i] = 0;     // terminator
  sp[shift + i + 1] = 0; // terminator
  int ienv = shift + i + 2;
  dlog("&env0=%p, &env2=%p\n", &sp[ienv], &sp[ienv + 2]);
  sp[ienv++] = 0;
  sp[ienv++] = 0;
#endif

  // TODO: there is a problem with alignment of auxv, which depends on the
  // number of arguments
  size_t *auxv = &sp[ienv];

#ifdef LKL
  if (strlen(me->sbox->disk_image)) {
    me->sbox->lkl_disk.fd = open(me->sbox->disk_image, O_RDWR);
    if (me->sbox->lkl_disk.fd < 0) {
      printf("cannot open disk '%s'\n", me->sbox->disk_image);
      while (1)
        ;
    }
  } else
    me->sbox->lkl_disk.fd = -1;

  me->sbox->lkl_disk.ops = &lkl_dev_blk_ops;
#endif

  //	printf("LOADER: argv = %lx, envp = %lx(expected %lx), auxv = %lx \n",
  //&sp[1], &sp[4], &sp[1 + 1 + sp[0]],auxv); 	printf("LOADER: argv = %s, envp =
  //%s, \n", sp[1], sp[4]);
#ifdef HYB_CVM
  auxv[0] = AT_BASE;
  auxv[1] = (unsigned long)me->sbox->base;
  auxv[2] = AT_ENTRY;
  auxv[3] = (unsigned long)me->func;
  auxv[4] = AT_PHDR;
  auxv[5] = mon_to_comp(me->sbox->base, me->sbox) + 0x40;
  auxv[6] = AT_PAGESZ;
  auxv[7] = 4096;
  auxv[8] = AT_IGNORE;
  auxv[9] = -1;

  int aid = 10;
  auxv[aid++] = AT_CLKTCK;
  auxv[aid++] = 100;
  auxv[aid++] = AT_HWCAP;
  auxv[aid++] = 0;
  auxv[aid++] = AT_EGID;
  auxv[aid++] = 0;
  auxv[aid++] = AT_EUID;
  auxv[aid++] = 0;
  auxv[aid++] = AT_GID;
  auxv[aid++] = 0;
  auxv[aid++] = AT_SECURE;
  auxv[aid++] = 0;
  auxv[aid++] = AT_UID;
  auxv[aid++] = -1;
  auxv[aid++] = AT_RANDOM;
  auxv[aid++] = 0;
  auxv[aid++] = AT_NULL;
  auxv[aid++] = 0;
#else
  int aid = 0;
  auxv[aid++] = AT_BASE;
  auxv[aid++] = 0;

  void *__capability bcap = pure_codecap_create((void *)me->sbox->base,
                                                me->sbox->base + CVM_MAX_SIZE);
  bcap = cheri_setaddress(bcap, me->sbox->base);
  st_cap(&auxv[aid], bcap);
  aid += 2;

  auxv[aid++] = AT_PHDR;
  auxv[aid++] = 0;
  auxv[aid++] = mon_to_comp(me->sbox->base, me->sbox) + 0x40;
  auxv[aid++] = 0;
  auxv[aid++] = AT_NULL;
  auxv[aid++] = 0;
  auxv[aid++] = 0;
  auxv[aid++] = 0;

  auxv[aid++] = AT_NULL;
  auxv[aid++] = 0;
  auxv[aid++] = 0;
  auxv[aid++] = 0;
#endif

  //    auxv[12]  = AT_EXECFN;	auxv[13]  = (size_t) "";
  //    auxv[22] = AT_PLATFORM;	auxv[23] = (size_t) "x86_64";
  //    auxv[28] = AT_RANDOM;	auxv[29] = getauxval(AT_RANDOM);
  //	auxv[aid++] = AT_HWCAP;		auxv[aid++] = getauxval(AT_HWCAP);

  //	if(mprotect(0x2fffd000, 4096, PROT_READ) == -1) {
  //		perror("mprotect");while(1);
  //	  }

#if SIM
#define CRTJMP(pc, sp)                                                         \
  __asm__ __volatile__("mv sp, %1 ; jr %0" : : "r"(pc), "r"(sp) : "memory")

  printf("SIM: sp = %p, tp = %p\n", sp, me->c_tp);
  printf("-----------------------------------------------\n");
  __asm__ __volatile__("mv sp, %0; mv tp, %1;" ::"r"(sp), "r"(me->c_tp)
                       : "memory");
  cinv(me->func,     // entrance
       NULL,         // entrance
       NULL,         // compartment data cap
       me->hostcall, // cap for exit
       NULL,         // cap for example
       NULL,         // default data cap after exit, must be changed
       me->sbox->ret_from_mon + me->sbox->base,
       auxv[1] /* AT_BASE */ + 0x0e000000 + 0x1000 // local_cap_store
  );

  printf("%s:%d\tBUG, die\n", __func__, __LINE__);
  while (1)
    ;

#else

  void *__capability sealed_codecap = me->sbox->box_caps.sealed_comp_pcc;
  void *__capability sealed_datacap = me->sbox->box_caps.sealed_comp_ddc;
  void *__capability dcap = me->sbox->box_caps.comp_ddc;
  void *__capability sealed_codecapt = me->sbox->box_caps.sealed_hc_pcc;
  void *__capability sealed_codecapt2 = me->sbox->box_caps.sealed_hc_pcc2;
  void *__capability sealed_datacapt = me->sbox->box_caps.sealed_mon_ddc;
  void *__capability sealed_ret_from_mon =
      me->sbox->box_caps.sealed_ret_from_mon;

  struct cinv_s cinv_args;

  cinv_args.caps[0] = sealed_codecap;
  dlog("ca0: sealed COMP PCC\n");
  CHERI_CAP_PRINT(cinv_args.caps[0]);

  cinv_args.caps[1] = sealed_datacap;
  dlog("ca1: sealed COMP DDC\n");
  CHERI_CAP_PRINT(cinv_args.caps[1]);

  cinv_args.caps[2] = dcap;
  dlog("ca2: COMP DDC\n");
  CHERI_CAP_PRINT(cinv_args.caps[2]);

  cinv_args.caps[3] = sealed_codecapt;
  dlog("ca3: sealed HC PCC\n");
  CHERI_CAP_PRINT(cinv_args.caps[3]);

  cinv_args.caps[4] = sealed_datacapt;
  dlog("ca4: sealed HC DDC (mon.DDC)\n");
  CHERI_CAP_PRINT(cinv_args.caps[4]);

  cinv_args.caps[5] = sealed_codecapt2;
  dlog("ca5: sealed OCALL PCC \n");
  CHERI_CAP_PRINT(cinv_args.caps[5]);

  cinv_args.caps[6] = sealed_ret_from_mon;
  dlog("ca6: sealed ret from mon\n");
  CHERI_CAP_PRINT(cinv_args.caps[6]);

  if (me->sbox->pure) {

    // TODO: this is very unreliable. we need to use precise bottom of the stack
    // here
    void *__capability sp_cap =
        datacap_create((void *)me->stack, (unsigned long)me->stack +
                                              (unsigned long)me->stack_size);
    sp_cap = cheri_setaddress(sp_cap, sp);

    cinv_args.caps[7] = sp_cap;
    dlog("ca7: SP cap for purecap cVMs\n");
    CHERI_CAP_PRINT(cinv_args.caps[7]);

    // NOTE: cvm c_tp is currently not capability
    void *__capability tp_cap = datacap_create(
        (void *)((unsigned long)me->c_tp), (unsigned long)me->c_tp + 4096);
    // TODO: is it feasible to set address using capability?
    tp_cap = cheri_setaddress(tp_cap, me->c_tp);

    cinv_args.caps[8] = tp_cap;
    dlog("ca8: TP cap for purecap cVMs\n");
    CHERI_CAP_PRINT(cinv_args.caps[8]);
  } else {
    // TODO: no arm_sim here
    sp = (void *)mon_to_comp((unsigned long)sp, me->sbox);
    me->c_tp = (void *)mon_to_comp((unsigned long)me->c_tp, me->sbox);
  }

  if (me->sbox->use_scl) {
    char *sh_st = malloc(4096 * 20);
    if (sh_st == NULL) {
      printf("can not allocate memory for shadow store, die\n");
      while (1)
        ;
    }

    void *__capability sh_st_cap = datacap_create(
        (void *)((unsigned long)sh_st), (unsigned long)sh_st + 4096 * 10);
    sh_st_cap = cheri_setaddress(sh_st_cap, sh_st);
    st_cap((void *)me->c_tp + 128, sh_st_cap);

    struct cap_relocs_s *cr = cvms[2].cr;
    unsigned int cr_number =
        cvms[2].cap_relocs_size / sizeof(struct cap_relocs_s);
    for (int j = 0; j < cr_number; j++) {
      void *__capability rel_cap;
      // Global/Constant, not Function capability reloc
      // Copy them to sh_st region
      // Multiple region share the same code(Function), but have different data
      // instances
      if (cr[j].perms != 0x8000000000000000ull) {
        dlog("TODO: DST = %p, Base: %p, Length: %ld\n", cr[j].dst, cr[j].addr,
             cr[j].len);
        dlog("COPYING OBJECTS: %lx, %lx, %ld\n",
             (unsigned long)sh_st + cr[j].addr, cvms[2].base + cr[j].addr,
             cr[j].len);
        memcpy((unsigned long)sh_st + cr[j].addr, cvms[2].base + cr[j].addr,
               cr[j].len);
      }
    }
  }

  dlog("[%3d ms]: finish init_thread\n", gettime());
  dlog("HW: sp = %p, tp = %p\n", sp, me->c_tp);
  dlog("-----------------------------------------------\n");
#ifdef HYB_CVM
  unsigned long *tp_args = me->c_tp + me->sbox->cmp_begin;
#else
  unsigned long *tp_args = (__cheri_fromcap unsigned long *)(me->c_tp);
#endif
  // note: local_cap_store addr, bottom of a reserved cvm stack with a page size
  tp_args[0] = me->sbox->top - me->sbox->stack_size + 0x1000;
  tp_args[1] = me->sbox->cid;

  profiler_end(&(profilers[SANDBOX_INIT]));

  profiler_begin(&(profilers[WORKLOAD_TOTAL]));
  profiler_begin(&(profilers[WORKLOAD_PREPARE]));

  uint64_t args_addr = &(cinv_args);

  mv_tp((unsigned long)me->c_tp);

  cinv(
#if 0
		  sealed_codecap,  	//ca0:	entrance
		  sealed_datacap,  	//ca1:	entrance
		  dcap, 			//ca2:	compartment data cap
///
		  sealed_codecapt,	//ca3:	cap for hostcalls
		  sealed_datacapt,	//ca4:	cap for hostcall, in fact -- sealed mon.DDC
///
		  sp_cap,
//		  sealed_codecapt2,	//ca5:	cap for ret from CINV2 (OCALL)
///
		  sealed_ret_from_mon, //ca6:	because compartment cannot create CAPS, this cap is created by MON prior calling
		  auxv[1] /* AT_BASE */ + 0x0e000000 + 0x1000 //local_cap_store
#else
      // auxv[1] /* AT_BASE */ + 0x0e000000 + 0x1000, // local_cap_store  //->
      // 0x2e001000
      tp_args[0], // local_cap_store address (per thread?)
      &cinv_args, sp
#endif
  );

  printf("something is wrong, die at init_thread %d\n", __LINE__);
  while (1)
    ;
#endif
}

int init_cvm_caps(struct s_box *cvm, struct c_thread *ct) {
  ct->sbox->box_caps.sealcap_size = sizeof(ct->sbox->box_caps.sealcap);
  if (sysctlbyname("security.cheri.sealcap", &ct->sbox->box_caps.sealcap,
                   &ct->sbox->box_caps.sealcap_size, NULL, 0) < 0) {
    printf("sysctlbyname(security.cheri.sealcap)\n");
    while (1)
      ;
  }
  // assert(ct->sbox == cvm);
  void *__capability ccap;
  if (cvm->pure)
    ccap = pure_codecap_create((void *)ct->sbox->cmp_begin,
                               (void *)ct->sbox->cmp_end);
  else
    ccap =
        codecap_create((void *)ct->sbox->cmp_begin, (void *)ct->sbox->cmp_end);
  ccap = cheri_setaddress(ccap, (unsigned long)(ct->func) +
                                    (unsigned long)(ct->sbox->base));

  void *__capability dcap =
      datacap_create((void *)ct->sbox->cmp_begin, (void *)ct->sbox->cmp_end);
  ct->sbox->box_caps.comp_ddc = dcap;

  ct->sbox->box_caps.sealed_comp_ddc =
      cheri_seal(dcap, ct->sbox->box_caps.sealcap);
  ct->sbox->box_caps.sealed_comp_pcc =
      cheri_seal(ccap, ct->sbox->box_caps.sealcap);
  if (ct->cb_out == NULL) {
    printf("callback_out is empty, use default 'monitor'\n");
    ct->cb_out = "monitor";
  }
  host_syscall_handler_prb(ct->cb_out, &ct->sbox->box_caps.sealed_hc_pcc,
                           &ct->sbox->box_caps.sealed_mon_ddc,
                           &ct->sbox->box_caps.sealed_hc_pcc2);

  // generate capabilitites for ret_from_mon. TODO: we should make them public
  // and our syscall/hostcall should fetch them todo: we need something better
  // than comp_to_mon_force
  ccap = cheri_setaddress(
      ccap, (unsigned long)comp_to_mon_force(
                (unsigned long)ct->sbox->ret_from_mon +
                    (unsigned long)ct->sbox->base -
                    (unsigned long)ct->sbox->cmp_begin,
                ct->sbox)); // here should be base but not cmp_begin.
  ct->sbox->box_caps.sealed_ret_from_mon =
      cheri_seal(ccap, ct->sbox->box_caps.sealcap);

  // if we have syscall handler, we should publish it. TODO: let's init thread
  // pubs this handler?
  if (cvm->syscall_handler != 0) {
    printf("ACHTUNG: '%s' has syscall handler 'syscall_handler' at %p\n",
           cvm->libos, cvm->syscall_handler);
    void *__capability syscall_pcc_cap = cheri_setaddress(
        ccap, (unsigned long)comp_to_mon_force(
                  cvm->syscall_handler + ct->sbox->base - ct->sbox->cmp_begin,
                  ct->sbox));
    void *__capability sealed_syscall_pcc_cap =
        cheri_seal(syscall_pcc_cap, ct->sbox->box_caps.sealcap);

    // note: use cur cvm's syscall handler cap here, the pcc2 is currently not
    // used, act just as a placeholder todo: figure out the syscall abi here
    host_syscall_handler_adv(cvm->libos, sealed_syscall_pcc_cap,
                             ct->sbox->box_caps.sealed_comp_ddc,
                             ct->sbox->box_caps.sealed_hc_pcc2);
  }
  // assert(ct->sbox == cvm);
}
