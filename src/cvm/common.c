#include "../monitor.h"
#include "../tfork/tfork.h"

extern int TFORK_FAILED;

int deploy_cvm(struct cvm *f)
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
    if (t_cid < 0)
    {
        // todo: sanitise base addresses, check cvms/sbox max number
        build_cvm(cid, // so far it is the best I can offer.
                  &comp,
                  f->runtime, /* libOS+init */
                  f->disk,    /* user disk */
                  c_argc,
                  c_argv,
                  f->cb_out,
                  f->cb_in);
    }
    else
    {
        fork_cvm(cid, t_cid, &comp, c_argc, c_argv);
    }
    // assert(cvms[cid].threads[0].sbox != 0);
    return cid;
}

int cvm_worker(struct cvm *f)
{
    printf("***************** Deploy '%s' ***************\n", f->name);
    printf("BUILDING cvm: name=%s, disk=%s, runtime=%s, net=%s, args='%s', base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, cb_in = '%s', cb_out = '%s' wait = %ds\n", f->name, f->disk, f->runtime, f->net, f->args, f->isol.base, f->isol.size, f->isol.begin, f->isol.end, f->cb_in, f->cb_out, f->wait);
    int cid = deploy_cvm(f);
    printf("BUILDING cvm complete: cid=%d, disk=%s, runtime=%s, base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, syscall_handler = '%ld', ret_from_mon = '%ld'\n", cid, cvms[cid].disk_image, cvms[cid].libos, cvms[cid].base, cvms[cid].box_size, cvms[cid].cmp_begin, cvms[cid].cmp_end, cvms[cid].syscall_handler, cvms[cid].ret_from_mon);
    struct s_box *cvm = &cvms[cid];
    if (cvm->t_cid < 2)
    {
        // is template
        init_thread(cid);
    }
    else
    {
        printf("load template, cid=%d, t_cid=%d\n", cid, cvm->t_cid);
        load(cid);
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
    int cid = f->isol.base / 0x10000000;
    printf("Deploy cthread of cvm, cid=%d\n", cid);
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
    ct->stack = cvm->cmp_end - ct->stack_size;

    int t_cid = find_template(cid, f->runtime);
    if (t_cid < 0)
    {
        cvm->t_cid = -1;
        init_pthread_stack(cvm);
    }
    else
    {
        cvm->t_cid = t_cid;
        printf("prepare to invoke tfork syscall, src_addr=%p, dst_addr=%p, len=%d\n", cvms[t_cid].cmp_begin, cvm->cmp_begin, cvm->box_size);
        if (tfork(cvms[t_cid].cmp_begin, cvm->cmp_begin, cvm->box_size) == TFORK_FAILED)
        {
            printf("tfork FAILED\n");
            exit(1);
        }
        printf("tfork complete\n");
    }

    // todo: maybe stack conflicts when exec load template.
    if (t_cid < 0)
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
        printf("ret = %d\n", ret);
        while (1)
            ;
    }

    ret = pthread_create(&ct->tid, &ct->tattr, cvm_worker, f);
    printf("pthread_create ret = %d\n", ret);
    if (ret != 0)
    {
        perror("pthread_create");
        exit(1);
    }

    printf("f->wait=%d\n", f->wait);
    if (f->wait == -1)
    {
        printf("pthread join, tid=%p, isol.base=%p\n", ct->tid, f->isol.base);
        void *cret;
        pthread_join(ct->tid, &cret);
        printf("join returned\n");
    }
    else
        sleep(f->wait);
}