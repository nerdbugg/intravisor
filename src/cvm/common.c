#include "monitor.h"
#include <assert.h>

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
    if ( !cvms[cid].use_tfork )
    {
        // todo: sanitise base addresses, check cvms/sbox max number
        build_cvm(cid, // so far it is the best I can offer.
                  f,
                  c_argc,
                  c_argv
                );
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
#ifdef DEBUG
    printf("***************** Deploy '%s' ***************\n", f->name);
    printf("BUILDING cvm: name=%s, disk=%s, runtime=%s, net=%s, args='%s', base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, cb_in = '%s', cb_out = '%s' wait = %ds\n", f->name, f->disk, f->runtime, f->net, f->args, f->isol.base, f->isol.size, f->isol.begin, f->isol.end, f->cb_in, f->cb_out, f->wait);
#endif
    int cid = deploy_cvm(f);
#ifdef DEBUG
    printf("BUILDING cvm complete: cid=%d, disk=%s, runtime=%s, base=0x%lx, size=0x%lx, begin=0x%lx, end=0x%lx, syscall_handler = '%ld', ret_from_mon = '%ld'\n", cid, cvms[cid].disk_image, cvms[cid].libos, cvms[cid].base, cvms[cid].box_size, cvms[cid].cmp_begin, cvms[cid].cmp_end, cvms[cid].syscall_handler, cvms[cid].ret_from_mon);
#endif
    struct s_box *cvm = &cvms[cid];
    if (!cvm->use_tfork)
    {
        // is template
        init_thread(cid);
    }
    else
    {
#ifdef DEBUG
        printf("load template, cid=%d, t_cid=%d\n", cid, cvm->t_cid);
#endif
        load_all_thread(cid);
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
#ifdef DEBUG
    printf("Deploy cthread of cvm, cid=%d\n", cid);
#endif
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
    cvm->t_cid = t_cid;
    cvm->fork = f->fork;
    cvm->use_tfork = (cvm->t_cid > 0) && cvm->fork;

    if (cvm->use_tfork == false)
    {
        init_pthread_stack(cvm);
    }
    else
    {
#ifndef TFORK
#ifdef DEBUG
			printf("prepare restore memory layout using template snapshot\n");
#endif
			map_entry* map_entry_list = cvm_map_entry_list[t_cid];
			assert(map_entry_list!=NULL);
			int fd = cvm_snapshot_fd[t_cid];
			assert(fd>0);

            // todo: find contiguous memory segments and merge mappings
            // todo: using mprotect to devide it into multiple segments
            map_entry *last = NULL;
            size_t map_size = 0;
            unsigned long map_start = NULL;
			unsigned long file_offset = 0l;
			map_entry* p = map_entry_list;
			while(p) {
				unsigned long old_begin	= cvms[t_cid].cmp_begin;
				unsigned long new_begin = cvm->cmp_begin;
				size_t size = p->end - p->start;
				unsigned long start = p->start - old_begin + new_begin;

                if(last==NULL || p->start==last->end) {
                    if(map_start == NULL) {
                        map_start = start;
                    }
                    map_size += size;
                } else {
                    // note: first mmap RWX, then using mprotect to restore p->prot
                    void* res = mmap(map_start, map_size, PROT_READ|PROT_WRITE|PROT_EXEC,
                                    MAP_PRIVATE, fd, file_offset);
                    assert(res!=MAP_FAILED);
                    file_offset += map_size;

                    map_size = size;
                    map_start = start;
                }
                last = p;
                p = p->next;
			}
            // note: the last iterattion
            if (last!=NULL) {
                    void* res = mmap(map_start, map_size, PROT_READ|PROT_WRITE|PROT_EXEC,
                                    MAP_PRIVATE, fd, file_offset);
                    assert(res!=MAP_FAILED);
            }

            // note: using mprotect to restore permissions
            p = map_entry_list;
            while(p) {
				unsigned long old_begin	= cvms[t_cid].cmp_begin;
				unsigned long new_begin = cvm->cmp_begin;
				size_t size = p->end - p->start;
				unsigned long start = p->start - old_begin + new_begin;

                int ret = mprotect(start, size, p->prot);
                assert(ret!=-1);

                p = p->next;
            }
#ifdef DEBUG
			printf("complete snapshot restoration\n");
#endif
#else
#ifdef DEBUG
			printf("prepare to invoke tfork syscall, src_addr=%p, dst_addr=%p, len=%d\n", cvms[t_cid].cmp_begin, cvm->cmp_begin, cvm->box_size);
#endif
			if (tfork(cvms[t_cid].cmp_begin, cvm->cmp_begin, cvm->box_size) == TFORK_FAILED) {
				printf("tfork FAILED\n");
				exit(1);
			}
#ifdef DEBUG
			printf("tfork complete\n");
#endif
#endif

    }

    // todo: maybe stack conflicts when exec load template.
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
#ifdef DEBUG
        printf("ret = %d\n", ret);
#endif
        while (1)
            ;
    }

    ret = pthread_create(&ct->tid, &ct->tattr, cvm_worker, f);
#ifdef DEBUG
    printf("pthread_create ret = %d\n", ret);
#endif
    if (ret != 0)
    {
        perror("pthread_create");
        exit(1);
    }

#ifdef DEBUG
    printf("f->wait=%d\n", f->wait);
#endif

    if (f->wait == -1)
    {
#ifdef DEBUG
        printf("pthread join, tid=%p, isol.base=%p\n", ct->tid, f->isol.base);
#endif
        void *cret;
        for (int i=0; true; i++) {
            if (ct[i].tid == NULL) {
                break;
            }
            pthread_join(ct[i].tid, &cret);
#ifdef DEBUG
            printf("cvm[%d]-thread[%d] has exited.\n", cid, i);
#endif
        }
#ifdef DEBUG
        printf("join returned\n");
#endif
    }
    else
        sleep(f->wait);
}