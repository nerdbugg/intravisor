#include "monitor.h"
#include <sys/thr.h>
#include <assert.h>

// asm.S
extern void cinv2(long, void *__capability, void *__capability, void *__capability);

void *c_thread_body(void *carg) {
	struct c_thread *me = (struct c_thread *)carg;

	long addr = (long) me->arg; //there is no mon_to_cap here because in all cases the args are cap-relative

	me->m_tp = (__cheri_fromcap void *)getTP();
	me->c_tp = (void *)(me->stack+4096);
	thr_self(&me->task_id);


#ifdef SIM
//	__asm__ __volatile__ ("mv ra, %0" : : "r"(ra): "memory" );
//	__asm__ __volatile__("mv tp, %0;" :: "r"(me->c_tp) : "memory");
//inline doesnt work like this
	cinv2(addr,
		  me->func,  	//entrance
		  NULL,  	//entrance
		  NULL 			//compartment data cap
		);


#else

//	printf("%p starting thread[%d]: [%lx -- %lx], func = %p, arg = %p\n",me, me->id, (long)me->stack, (long)me->stack+me->stack_size, me->func, me->arg);

	void * __capability sealcap;
	size_t sealcap_size;

	sealcap_size = sizeof(sealcap);

#ifdef	__FreeBSD__
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0) {
		printf("sysctlbyname(security.cheri.sealcap)\n");while(1);
	}
#else
	printf("sysctlbyname security.cheri.sealcap is not implemented in your OS\n");
#endif

	void * __capability ccap = codecap_create((void*)me->sbox->cmp_begin, (void*)me->sbox->cmp_end);
	ccap = cheri_setaddress(ccap, (unsigned long) me->func);
	void * __capability dcap = datacap_create((void *) me->sbox->cmp_begin, (void *) me->sbox->cmp_end);

	void * __capability sealed_datacap = cheri_seal(dcap, sealcap);
	void * __capability sealed_codecap = cheri_seal(ccap, sealcap);

	me->c_tp = mon_to_comp(me->c_tp, me->sbox);

repeat:

	mv_tp((unsigned long)me->c_tp);
	// note: change sp to comparted-mode in cinv2
	
//inline doesnt work like this
	cinv2(addr,
		  sealed_codecap,  	//entrance
		  sealed_datacap,  	//entrance
		  dcap 			//compartment data cap
		);

	mv_tp((unsigned long)me->m_tp);
	goto repeat;

#endif

	printf("stuck in thread, die\n");
	while(1);
}

void destroy_carrie_thread(struct c_thread *ct) {
	pthread_t tid = pthread_self();
	pthread_mutex_lock(&ct->sbox->ct_lock);
	for(int i = 0; i < MAX_THREADS; i++) {
		if(ct[i].tid == tid) {
			ct[i].id = -1;
  			pthread_mutex_unlock(&ct->sbox->ct_lock);
//			printf("thread %d exited\n", i);
#ifdef LKL
			lkl_host_ops.thread_exit();
#else
			if(ct->sbox->cid > 2) {
				printf("EXIT ON < 0.95X\n");
				exit(0);
			}
			pthread_exit(NULL);
#endif
			// todo: is below code reachable?
			// note: munmap temp stack (used in snapshot restoring)
			int res=munmap(ct->temp_stack, TEMP_STACK_SIZE);
		}
	}
	pthread_mutex_unlock(&ct->sbox->ct_lock);
	printf("something is wrong with the thread, check %p. (may be wrong with sbox->ct->m_tp/c_tp ?)\n", tid);
	while(1);
}

#ifdef LKL

struct thread_bootstrap_arg {
	struct thread_info *ti;
	int (*f)(void *);
	void *arg;
};

long create_carrie_thread(struct c_thread *ct, void *f, void *arg) {
again:
	pthread_mutex_lock(&ct->sbox->ct_lock);
	int j;
	for(j = 0; j < MAX_THREADS; j++) {
		if(ct[j].id == -1)
			break;
	}
	if(j == MAX_THREADS) {
//		printf("need more threads, die\n");
//		exit(1);
		pthread_mutex_unlock(&ct->sbox->ct_lock);
		usleep(100);
		goto again;
	}

	int tmp = j;

	ct[tmp].id = tmp;
	pthread_mutex_unlock(&ct->sbox->ct_lock);

	int ret = pthread_attr_init(&ct[tmp].tattr);
	if(ret != 0) {
		perror("attr init");printf("ret = %d\n", ret); while(1);
	}

	ct[tmp].stack_size = STACK_SIZE;
	ct[tmp].stack = (void *)(ct[tmp].sbox->cmp_end - ct[tmp].stack_size*(ct[tmp].id+1));

	ret = pthread_attr_setstack(&ct[tmp].tattr, ct[tmp].stack, ct[tmp].stack_size);
	if(ret != 0) {
		perror("pthread attr setstack");printf("ret = %d\n", ret);
	}

	ct[tmp].arg = arg;
	ct[tmp].func = comp_to_mon(f, ct[tmp].sbox);

	struct thread_bootstrap_arg *targ = (struct thread_bootstrap_arg *) (comp_to_mon(arg, ct[tmp].sbox));
	void *targ_f = NULL;
	void *targ_arg = NULL;
//	printf("arg = %p, targ = %p\n", arg, targ);
	if(arg) {
		targ_f = targ->f;
		targ_arg = targ->arg;
	} 

//	printf("CARRIE_THREAD %d %p, [%lx -- %lx], guessing (%p %p)\n", tmp, ct[tmp].func, ct[tmp].stack, ct[tmp].stack+STACK_SIZE, targ_f, targ_arg);

#ifdef __linux__
	ret  = pthread_attr_setaffinity_np(&ct[tmp].tattr, sizeof(ct[tmp].sbox->cpuset), &ct[tmp].sbox->cpuset);
	if (ret != 0) {
		perror("pthread set affinity");printf("ret = %d\n", ret);
	}
#endif

	ret = pthread_create(&ct[tmp].tid, &ct[tmp].tattr, c_thread_body, &ct[tmp]);
	if(ret != 0) {
		perror("pthread create");printf("ret = %d\n", ret);while(1);
	}

	return (long) ct[tmp].tid;
}

#endif

// todo: using old ABI, morello version using $tp to save cid
struct c_thread *get_cur_thread() {
	int cid = (long) getSP() / 0x10000000;
	if ((cid <= 0 ) || (cid >= MAX_CVMS) ) {
		printf("wrong cvm id %d, sp = %p, die\n", cid, getSP()); while(1);
	}

// would be nice to check something
	struct c_thread *ret = &cvms[cid].threads[ (cvms[cid].cmp_end - (((long) getSP() / STACK_SIZE)*STACK_SIZE))/STACK_SIZE - 1];

	return ret;
}

void* get_cur_localcapstore()
{
	struct c_thread* ct = get_cur_thread();
	void* base = ct->sbox->base;
	return base+0xe001000;
}

