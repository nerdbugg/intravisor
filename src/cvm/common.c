#include <assert.h>

#include "monitor.h"
#include "common/log.h"
#include "common/utils.h"
#include "restore.h"
#include "hostcalls/fs/fd.h"

extern void *run_cvm(int cid);
extern int init_pthread_stack(struct s_box *cvm);
extern int init_cvm(int cid, struct cvm *f, int argc, char *argv[]);
extern int fork_cvm(int cid, int t_cid, struct cmp_s *cmp, int argc, char *argv[]);

int build_cvm(struct cvm *f)
{
    int cid = f->isol.base / 0x10000000;

    enum
    {
        kMaxArgs = 16
    };
    int c_argc = 0;
    long *c_argv = malloc(kMaxArgs * sizeof(long));

    char *p2 = strtok(f->args, " ");
    while (p2 && c_argc < kMaxArgs - 1)
    {
        c_argv[c_argc++] = p2;
        p2 = strtok(0, " ");
    }
    c_argv[c_argc] = 0;
    struct cmp_s comp;
    comp.base = f->isol.base;   /* base addr */
    comp.size = f->isol.size;   /* size */
    comp.begin = f->isol.begin; /* cmp_begin */
    comp.end = f->isol.end;     /* cmp_end  */
    int t_cid = cvms[cid].t_cid;
    if ( !cvms[cid].use_tfork )
    {
        // todo: sanitise base addresses, check cvms/sbox max number
        // so far it is the best I can offer.
        init_cvm(cid, f, c_argc, (char**)c_argv);
    }
    else
    {
        fork_cvm(cid, t_cid, &comp, c_argc, (char**)c_argv);
    }
    // assert(cvms[cid].threads[0].sbox != 0);
    return cid;
}

int cvm_worker(struct cvm *f)
{
    dlog("***************** [%d] Deploy '%s' ***************\n", f->isol.base/CVM_MAX_SIZE, f->name);
    dlog("BUILDING cvm: name=%s, disk=%s, runtime=%s, net=%s, args='%s', base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, cb_in = '%s', cb_out = '%s' wait = %ds\n", f->name, f->disk, f->runtime, f->net, f->args, f->isol.base, f->isol.size, f->isol.begin, f->isol.end, f->cb_in, f->cb_out, f->wait);

    int cid = build_cvm(f);
    dlog("BUILDING cvm complete: cid=%d, disk=%s, runtime=%s, base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, syscall_handler = '%ld', ret_from_mon = '%ld'\n", cid, cvms[cid].disk_image, cvms[cid].libos, cvms[cid].base, cvms[cid].box_size, cvms[cid].cmp_begin, cvms[cid].cmp_end, cvms[cid].syscall_handler, cvms[cid].ret_from_mon);

    struct s_box *cvm = &cvms[cid];
    if (!cvm->use_tfork)
    {
        // is template
        run_cvm(cid);
    }
    else
    {
        dlog("load template, cid=%d, t_cid=%d\n", cid, cvm->t_cid);
        restore_from_template(cid);
    }
}

int find_template(int cid, char *libos)
{
    if (cid == 2)
    {
        return -1;
    }
    for (int i = 0; i < MAX_CVMS; i++)
    {
        if (strcmp(libos, cvms[i].libos) == 0)
        {
            return i;
        }
    }
    return -1;
}

void create_and_start_cvm(struct cvm *f)
{
    int cid = f->isol.base / CVM_MAX_SIZE;
    dlog("Deploy cthread of cvm, cid=%d\n", cid);

    struct s_box *cvm = &cvms[cid];
    struct c_thread *ct = cvm->threads;

    cvm->start_time = get_ms_timestamp();

    if (pthread_mutex_init(&cvm->ct_lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        exit(1);
    }
    int ret;
    ret = pthread_attr_init(&ct->tattr);
    if (ret != 0)
    {
        perror("attr init");
        printf("ret = %d\n", ret);
        while (1)
            ;
    }

    cvm->cmp_begin = f->isol.begin;
    cvm->cmp_end = f->isol.end;
    cvm->box_size = f->isol.size;
    ct->stack_size = (MAX_THREADS + 1) * STACK_SIZE;
    ct->stack = (void*)(cvm->cmp_end - ct->stack_size);

    int t_cid = find_template(cid, f->runtime);
    cvm->t_cid = t_cid;
    cvm->fork = f->fork;
    cvm->use_tfork = (cvm->t_cid > 0) && cvm->fork;
    // init cvm fdtable
    fdtable_init(&(cvm->fdtable));

    if (cvm->use_tfork == false) {
        init_pthread_stack(cvm);
    }
    else {
        restore_cvm_region(cvm, &(cvms[t_cid]));
    }
    

    // TODO: maybe stack conflicts when exec load template.
    if (cvm -> use_tfork)
    {
        ret = pthread_attr_setstack(&ct->tattr, ct->stack, ct->stack_size);
    }
    else
    {
        ret = pthread_attr_setstack(&ct->tattr, ct->stack, ct->stack_size);
    }

    if (ret != 0)
    {
        perror("pthread attr setstack");
        dlog("ret = %d\n", ret);
        while (1)
            ;
    }

    ret = pthread_create(&ct->tid, &ct->tattr, cvm_worker, f);

    dlog("pthread_create ret = %d\n", ret);
    if (ret != 0)
    {
        perror("pthread_create");
        exit(1);
    }

    dlog("f->wait=%d\n", f->wait);

    if (f->wait == -1)
    {
        dlog("pthread join, tid=%p, isol.base=%p\n", ct->tid, f->isol.base);

        void *cret;
        for (int i=0; true; i++) {
            if (ct[i].tid == NULL) {
                break;
            }
            pthread_join(ct[i].tid, &cret);

            dlog("cvm[%d]-thread[%d] has exited.\n", cid, i);
        }

        dlog("join returned\n");
    }
    else
        sleep(f->wait);
}
