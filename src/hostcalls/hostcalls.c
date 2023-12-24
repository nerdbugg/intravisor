#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>

#include "common/log.h"
#include "monitor.h"
#include "tfork.h"
#include "common/profiler.h"
#include "common/utils.h"
#include "carrier_thread.h"
#include "hostcall_tracer.h"
#include "host_syscall_callbacs.h"
#include "hostcalls/fs/fd.h"
#include "host_num.h"


// static __inline__ void * getSP

int wrap_write(int fd, void *ptr, int size) {
//	__syscall3(64, 1, (long )ptr, size);

//	int ret = write(STDOUT_FILENO, ptr, size);
	int ret = write(fd, ptr, size);

	return ret;
}

///////////////////////////
/*
0	const char *virtio_devices;
//1	void (*print)(const char *str, int len);
2	void (*panic)(void);
//3	struct lkl_sem* (*sem_alloc)(int count);
//4	void (*sem_free)(struct lkl_sem *sem);
//5	void (*sem_up)(struct lkl_sem *sem);
//6	void (*sem_down)(struct lkl_sem *sem);
//7	struct lkl_mutex *(*mutex_alloc)(int recursive);
//8	void (*mutex_free)(struct lkl_mutex *mutex);
//9	void (*mutex_lock)(struct lkl_mutex *mutex);
//10	void (*mutex_unlock)(struct lkl_mutex *mutex);
//11	lkl_thread_t (*thread_create)(void (*f)(void *), void *arg);
12	void (*thread_detach)(void);
13	void (*thread_exit)(void);
14	int (*thread_join)(lkl_thread_t tid);
//15	lkl_thread_t (*thread_self)(void);
16	int (*thread_equal)(lkl_thread_t a, lkl_thread_t b);
17	struct lkl_tls_key *(*tls_alloc)(void (*destructor)(void *));
18	void (*tls_free)(struct lkl_tls_key *key);
19	int (*tls_set)(struct lkl_tls_key *key, void *data);
20	void *(*tls_get)(struct lkl_tls_key *key);
21	void* (*mem_alloc)(unsigned long);
22	void (*mem_free)(void *);
23	void* (*mem_executable_alloc)(unsigned long);
24	void (*mem_executable_free)(void *, unsigned long size);
25	unsigned long long (*time)(void);
26	void* (*timer_alloc)(void (*fn)(void *), void *arg);
27	int (*timer_set_oneshot)(void *timer, unsigned long delta);
28	void (*timer_free)(void *timer);
29	void* (*ioremap)(long addr, int size);
30	int (*iomem_access)(const __volatile__ void *addr, void *val, int size,
			    int write);
31	long (*gettid)(void);
32	void (*jmp_buf_set)(struct lkl_jmp_buf *jmpb, void (*f)(void));
33	void (*jmp_buf_longjmp)(struct lkl_jmp_buf *jmpb, int val);
*/
///////////////////////////

int open_tap(char *ifname) {
#if __FreeBSD__
	return open(ifname, O_RDWR | O_NONBLOCK);
#else
	printf("%s %d not implemented\n", __FILE__, __LINE__);
#if 0
//__linux__
	struct lkl_netdev *nd;
	int fd, vnet_hdr_sz = 0;

	struct ifreq ifr = {
		.ifr_flags = IFF_TAP | IFF_NO_PI,
	};

	strncpy(ifr.ifr_name, "tap0", IFNAMSIZ);

	int ret, tap_arg = 0;
#if 0
	if (offload & BIT(LKL_VIRTIO_NET_F_GUEST_CSUM))
		tap_arg |= TUN_F_CSUM;
	if (offload & (BIT(LKL_VIRTIO_NET_F_GUEST_TSO4) |
	    BIT(LKL_VIRTIO_NET_F_MRG_RXBUF)))
		tap_arg |= TUN_F_TSO4 | TUN_F_CSUM;
	if (offload & (BIT(LKL_VIRTIO_NET_F_GUEST_TSO6)))
		tap_arg |= TUN_F_TSO6 | TUN_F_CSUM;

	if (tap_arg || (offload & (BIT(LKL_VIRTIO_NET_F_CSUM) |
				   BIT(LKL_VIRTIO_NET_F_HOST_TSO4) |
				   BIT(LKL_VIRTIO_NET_F_HOST_TSO6)))) {
		ifr->ifr_flags |= IFF_VNET_HDR;
		vnet_hdr_sz = sizeof(struct lkl_virtio_net_hdr_v1);
	}
#endif

	fd = open("/dev/net/tun", O_RDWR|O_NONBLOCK);
	if (fd < 0) {
		perror("open");
		return NULL;
	}

	ret = ioctl(fd, TUNSETIFF, ifr);
	if (ret < 0) {
		fprintf(stderr, "%s: failed to attach to: %s\n",
			"/dev/net/tun", strerror(errno));
		close(fd);
		return NULL;
	}

	if (vnet_hdr_sz && ioctl(fd, TUNSETVNETHDRSZ, &vnet_hdr_sz) != 0) {
		fprintf(stderr, "%s: failed to TUNSETVNETHDRSZ to: %s\n",
			"/dev/net/tun", strerror(errno));
		close(fd);
		return NULL;
	}

	if (ioctl(fd, TUNSETOFFLOAD, tap_arg) != 0) {
		fprintf(stderr, "%s: failed to TUNSETOFFLOAD: %s\n",
			"/dev/net/tun", strerror(errno));
		close(fd);
		return NULL;
	}

	return fd;
#endif
#endif
}


#ifndef SIM
void cinv2(long, void *__capability, void *__capability, void *__capability);
#else
void cinv2(long, void *, void *, void *);
#endif


long host_make_call(struct c_thread *ct, void *f, void *arg) {
	pthread_mutex_lock(&ct->sbox->ct_lock);
	int j;
	for(j = 0; j < MAX_THREADS; j++) {
		if(ct[j].id == -1)
			break;
	}
	if(j == MAX_THREADS) {
		printf("need more threads, die\n");
		exit(1);
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
	ct[tmp].func = f;
//printf("HOST_CALL: CARRIE_THREAD %d %p %p\n", tmp, f, getSP());
	ret = pthread_create(&ct[tmp].tid, &ct[tmp].tattr, c_thread_body, &ct[tmp]);
	if(ret != 0) {
		perror("pthread create");printf("ret = %d\n", ret);
	}

	pthread_join(ct[tmp].tid, NULL);

	return 0; //todo: here should be return value
}



#ifdef LKL

struct s_thread {
	void *f;
	void *arg;
};

//this is very wrong, needs rework
void *timer_f = NULL;

void create_timer_thread(void *arg) {
	create_carrie_thread(cvms[0].threads, timer_f, arg);
}

long create_carrie_timer(void *f, void *arg) {
	timer_f = f;

	return (long) lkl_host_ops.timer_alloc(create_timer_thread, arg);
}

#endif


/************************ HOSTCALLs **************/

//the most of the calls are related to MUSL-LKL. They should be separated from basic calls. Ideally, moved into the runtime/musllkl directory and loaded as shared library.
long hostcall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
	long t5 = (long) getT5();

	int cid = (long) getSP() / 0x10000000;
	int ct_id = (cvms[cid].cmp_end - (((long) getSP() / STACK_SIZE)*STACK_SIZE))/STACK_SIZE - 1;
	struct c_thread *ct = get_cur_thread();
	ct->c_tp = getTP();

	mv_tp((unsigned long)ct->m_tp);

#ifdef HC_TRACE
	hostcall_trace("%d\n", t5);
#endif

#if 0
//	if ( (ct->id !=1) && debug_calls)
		printf("IN: [%d]:%d %p, %p, [%lx %lx %lx %lx] \n", ct->id, t5, getSP(), getTP(), a0, a1, a2, a3);
#endif
	long ret = 0;
//	struct lkl_disk *disk;
	switch(t5) {
		case 1:
			// wrap_write(ct->sbox->fd, (void *)comp_to_mon(a0, ct->sbox), a1);
      fprintf(stdout, (void *)comp_to_mon(a0, ct->sbox), a1, a2, a3);
//			wrap_write(ct->sbox->fd, a0, a1);
			break;
#ifdef LKL
//NB: we don't translate sem/mutex-related addresses because they are not used inside compartments
		case 3:
			ret = (long) lkl_host_ops.sem_alloc(a0);
			break;
		case 4:
			lkl_host_ops.sem_free(a0);
			break;
		case 5:
			lkl_host_ops.sem_up(a0);
			break;
		case 6:
			lkl_host_ops.sem_down(a0);
			break;
		case 7:
			ret = (long) lkl_host_ops.mutex_alloc(a0);
			break;
		case 8:
			lkl_host_ops.mutex_free(a0);
			break;
		case 9:
			lkl_host_ops.mutex_lock(a0);
			break;
		case 10:
			lkl_host_ops.mutex_unlock(a0);
			break;
		case 11:
			ret = (long) create_carrie_thread(ct->sbox->threads, a0, a1);
			break;
		case 12:
			lkl_host_ops.thread_detach();
			break;
		case 13:
			destroy_carrie_thread(ct->sbox->threads);
			break;
		case 14:
			ret = (long) lkl_host_ops.thread_join(a0);
			break;
		case 15:
			ret = (long) lkl_host_ops.thread_self();
			break;
		case 16:
			ret = (long) lkl_host_ops.thread_equal(a0, a1);
			break;
		case 17:
			ret = (long) lkl_host_ops.tls_alloc(a0);
			break;
		case 18:
			lkl_host_ops.tls_free(a0);
			break;
		case 19:
			ret = (long) lkl_host_ops.tls_set(a0, a1);
			break;
		case 20:
			ret = (long) lkl_host_ops.tls_get(a0);
			break;
		case 21:
printf("MEM_ALLOC, who called?\n"); while(1);
			ret = (long) lkl_host_ops.mem_alloc(a0);
			break;
		case 22:
printf("MEM_FREE %p, who called?\n", a0); while(1);
			lkl_host_ops.mem_free(a0);
			break;
		case 23:
printf("EXEC ALLOC %p, who called?\n", a0); while(1);
			ret = (long) lkl_host_ops.mem_executable_alloc(a0);
			break;
		case 24:
printf("EXEC FREE %p, who called?\n", a0); while(1);
			lkl_host_ops.mem_executable_free(a0, a1);
			break;
		case 25:
			ret = (long) lkl_host_ops.time();
			break;
		case 26:
			printf("TODO: CREATE_CARRIE_TIMER\n");
			ret = (long) create_carrie_timer(a0, a1);
			break;
		case 27:
			if(timers) {
				printf("TODO: SET_ONE_SHOT\n");
				ret = (long) lkl_host_ops.timer_set_oneshot(a0, a1);
			}
			break;
		case 28:
			printf("TODO: TIMER_FREE\n");
			lkl_host_ops.timer_free(a0);
			break;
/////
//disk I/O
/////
		case 100:
			ret = (long) lkl_dev_blk_ops.request(ct->sbox->cmp_begin, ct->sbox->lkl_disk, a1);
			break;
		case 101:
			ret = (long) lkl_dev_blk_ops.get_capacity(ct->sbox->cmp_begin, ct->sbox->lkl_disk, a1);
			break;
////
//INSPECT
////
		case 114:
			ret = (ct->sbox->t_cid == -1);
			break;
///
//SAVE
/// 
		case 115:
			// when cvm is configured fork:0, just return
			if (!ct->sbox->fork)
				break;
			ct->notified = true;
			if (ct == ct->sbox->threads) {
				notify_other_thread_save(ct);
			}
			break;
////
//NETWORK
////
		case 200:
			ret = (long) fd_net_ops.tx(comp_to_mon(a0, ct->sbox), comp_to_mon(a1, ct->sbox), a2);
			break;
		case 201:
			ret = (long) fd_net_ops.rx(comp_to_mon(a0, ct->sbox), comp_to_mon(a1, ct->sbox), a2);
			break;
		case 202:
			ret = (long) fd_net_ops.poll(comp_to_mon(a0, ct->sbox));
			break;
		case 203:
			printf("TODO: %d\n", __LINE__);
			fd_net_ops.poll_hup(a0);
			break;
		case 204:
			printf("TODO: %d\n", __LINE__);
			fd_net_ops.free(a0);
			break;
#else
		// exit
		case 13:
			destroy_carrie_thread(ct->sbox->threads);
			break;
		// nanosleep
		case 200:
			ret = nanosleep((struct timespec*)comp_to_mon(a0, ct->sbox),
					(struct timespec*)comp_to_mon(a1, ct->sbox));
			break;
////
//INSPECT
////
		case 114:
			ret = (ct->sbox->t_cid == -1);
			break;
///
//SAVE
/// 
		case 115:
      profiler_end(&(profilers[WORKLOAD_PREPARE]));

      profiler_begin(&(profilers[SNAPSHOT_GEN]));

			// save hostcall no effect when configured is_template false
			if (!ct->sbox->is_template) {
        // NOTE: test in single cvm case
        profiler_begin(&(profilers[WORKLOAD_EXECUTE]));
				break;
      }

			ct->notified = true;
			if (ct == ct->sbox->threads) {
				notify_other_thread_save(ct);
			}

      printf("save this cvm, cid=%d\n", sboxptr_to_cid(ct->sbox));
      save_cur_thread_and_exit(sboxptr_to_cid(ct->sbox), ct);
			break;
    case 116: {
      char* buf = (char*)comp_to_mon(a0, ct->sbox);
      size_t len = a1;
      char** argv = ct->argv;
      char* arg = argv[0];
      size_t argc = ct->argc;
      size_t arg_size = strlen(arg);
      if(arg==NULL) {
        printf("[intravisor/hostcall] no argv set in c_thread\n");
        ret = 1;
      }
      if(arg_size+1>len) {
        printf("[intravisor/hostcall] arg size larger than buf\n");
        ret = 1;
      }

      dlog("[intravisor/hostcall] ct->argv = %s\n", arg);

      strncpy(buf, arg, len);
      ret = 0;
      break;
    }
#endif
////
//HOST CALLS
//// these 3 calls are used for networking. 
		case 300:
//			ret = open(a0, a1); //FreeBSD and musl have different Flags
			ret = (long) open_tap((char*)comp_to_mon(a0, ct->sbox));
			break;
		case 301:
			ret = (long) pipe((int*)comp_to_mon(a0, ct->sbox));
			break;
		case 302:
			ret = (long) fcntl(a0, F_SETFL, O_NONBLOCK); //see the comment above
			break;
////
		case 400:
		case 401:
		case 402:
			printf("deprecated %ld\n", t5); while(1);
		case 403:
			printf("TODO: %d\n", __LINE__);
			ret = (long) host_make_call(ct->sbox->threads, (void*)comp_to_mon(a0, ct->sbox), (void*)a1);
			break;
		case 404:
			printf("deprecated %ld\n", t5); while(1);
			break;
		case 405:
			printf("TODO: %d\n", __LINE__);
			ret = (long) host_cap_file_adv(comp_to_mon(a0, ct->sbox), a1, comp_to_mon(a2, ct->sbox));
			break;
		case 406:
			ret = (long) host_cap_file_prb(comp_to_mon(a0, ct->sbox), comp_to_mon(a1, ct->sbox), comp_to_mon(a2, ct->sbox));
			break;
		case 407:
			host_cap_wait((int)a0);
			break;
		case 408:
			host_cap_wake((int)a0);
			break;
		case 409:
			ret = (long) host_cap_stream_adv(ct->sbox->threads, comp_to_mon(a0, ct->sbox), a1, comp_to_mon(a2, ct->sbox));
			break;
		case 410:
			ret = (long) host_cap_stream_prb(comp_to_mon(a0, ct->sbox));
			break;
		case 411:
			ret = (long) host_make_cap_call(ct->sbox->threads, a0, comp_to_mon(a1, ct->sbox), a2);
			break;
		case 412:
			ret = (long) host_finish_cap_call(a0, comp_to_mon(a1, ct->sbox));
			break;
		case 413:
			ret = (long) host_fetch_cap_call(a0, comp_to_mon(a1, ct->sbox), comp_to_mon(a2, ct->sbox));
			break;


// note: forward syscall to host kernel
#define USE_HOST_NET
#ifdef USE_HOST_NET
		case 500:
			ret = (int) socket(a0, a1, a2);
//			printf("ret = %d, a0 = %d a1 = %d a2 = %d\n", ret, a0, a1, a2);perror("socket");
			break;
		case 501:
			ret = (int) setsockopt(a0, a1, a2, comp_to_mon(a3, ct->sbox), a4);
//			printf("ret = %d, a0 = %d a1 = %d a2 = %d %d %d \n", ret, a0, a1, a2, a3, a4);perror("setcodk");
			break;
		case 502:
			ret = (int) ioctl(a0, a1, a2);
//			printf("ret = %d %d %d %ld %ld\n", ret, a0, a1, a2, FIONBIO);
//			perror("ioctl");
			break;
		case 503:
			ret = (int) accept4((int) a0, 
						(struct sockaddr *) comp_to_mon(a1, ct->sbox), 
						(socklen_t *) comp_to_mon(a2,ct->sbox), 
						(int) a3);
			break;
		case 504:
			ret = (int) listen(a0, a1);
			break;
		case 505:
			ret = (int) accept((int) a0, 
						(struct sockaddr *) comp_to_mon(a1, ct->sbox), 
						(socklen_t *) comp_to_mon(a2, ct->sbox));
			break;
		case 506:
			ret = (int) bind(a0, 
						(const struct sockaddr *) comp_to_mon(a1, ct->sbox),
						a2);
			break;
		case 507:
      ret = cvm_write(ct->sbox, (int)a0, (char*)comp_to_mon(a1, ct->sbox), (size_t)a2);
			break;
		case 508:
      ret = cvm_read(ct->sbox, (int)a0, (char*)comp_to_mon(a1, ct->sbox), (size_t)a2);
			break;
		case 509:
			ret = send((int) a0, 
					(void *) comp_to_mon(a1, ct->sbox),
					(size_t) a2, (int) a3);
			break;
		case 510:
			ret = recv((int) a0,
					(void *) comp_to_mon(a1, ct->sbox),
					(size_t) a2, (int) a3);
			break;
		case 511:
			ret = (int) close((int) a0);
			break;
		case 512:
			ret = (int) socketpair((int) a0, (int) a1, (int) a2, (int*)a3);
			break;
#if 0
#ifdef __linux__
		case 513:
			ret = epoll_create((int) a0);
			break;
		case 514:
			ret = epoll_create1((int) a0);
			break;
		case 515:
			ret = eventfd((unsigned int) a0, (int) a1);
			break;
		case 516:
			ret = epoll_ctl((int) a0, (int) a1, (int) a2, (struct epoll_event *)a3);
			break;
		case 517:
			ret = epoll_wait((int) a0, (struct epoll_event *)a1, (int) a2, (int) a3);
			break;
		case 518:
			ret = epoll_pwait((int) a0, (struct epoll_event *) a1, (int) a2, (int) a3, (sigset_t *) a4);
			break;
#endif
#else
		case 513:
			ret = poll(comp_to_mon(a0, ct->sbox), a1, a2);
			break;
		case 514:
			ret = select(a0, 
					(fd_set*) comp_to_mon(a1, ct->sbox),
					(fd_set*) comp_to_mon(a2, ct->sbox),
					(fd_set*) comp_to_mon(a3, ct->sbox),
					(struct timeval*) comp_to_mon(a4, ct->sbox));
			break;
#endif
		case 519:
			ret = recvfrom((int) a0, (void *restrict ) a1, (size_t) a2, (int) a3, (struct sockaddr *restrict) a4, (socklen_t *restrict) a5);
			break;
		case 520:
			ret = writev((int) a0, (const struct iovec *) a1, (int) a2);
			break;
#endif
		case 530:
			// int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
			ret = getaddrinfo((char*) comp_to_mon(a0, ct->sbox),
						(char*) comp_to_mon(a1, ct->sbox),
						(struct addrinfo*) comp_to_mon(a2, ct->sbox),
						(struct addrinfo**) comp_to_mon(a3, ct->sbox));
			break;
		case 531:
			ret = getpeereid(a0, (uid_t*)comp_to_mon(a1, ct->sbox), (gid_t*)comp_to_mon(a2, ct->sbox));
			break;
		case 532:
			ret = connect(a0, (struct sockaddr*) comp_to_mon(a1, ct->sbox), a2);
			break;

		case 700:
			ret = host_get_my_inner(ct->sbox, comp_to_mon(a0, ct->sbox));
			break;
		case 701:
			ret = host_syscall_handler_prb((char*)comp_to_mon(a0, ct->sbox),
							(void*)comp_to_mon(a1, ct->sbox),
							(void*)comp_to_mon(a2, ct->sbox),
							(void*)comp_to_mon(a3, ct->sbox));
			break;
		case 702:
			ret = host_get_sc_caps(a0, a1, a2);
			break;

		case 800:
			ret = gettimeofday((struct timeval*)comp_to_mon(a0, ct->sbox), 
						(struct timezone*)comp_to_mon(a1, ct->sbox));
			break;
		case 801:
			ret = lstat((char*)comp_to_mon(a0, ct->sbox), (struct stat*)comp_to_mon(a1, ct->sbox));
			break;
		case 806:
			ret = stat((char*)comp_to_mon(a0, ct->sbox), (struct stat*)comp_to_mon(a1, ct->sbox));
			break;
		case 807:
			ret = fstat(a0, (struct stat*)comp_to_mon(a1, ct->sbox));
//			printf("fstat: st_dev = %x, st_ino = %x\n", statbuf.st_dev, statbuf.st_ino);
			break;
		case 802:
			ret = unlink((char*)comp_to_mon(a0, ct->sbox));
			break;
		case CLOSE:
      ret = cvm_close(ct->sbox, (int)a0);
			break;
		case 804:
			ret = access((char*)comp_to_mon(a0, ct->sbox), a1);
			break;
		case 808:
			ret = truncate((char*)comp_to_mon(a0, ct->sbox), a1);
			break;
		case READ:
//			printf("read = %d, %p, %d\n", a0, comp_to_mon(a1, ct->sbox), a2);
      ret = cvm_read(ct->sbox, (int)a0, (char*)comp_to_mon(a1, ct->sbox), (size_t)a2);
//			printf("read ret = %d\n", ret);
			break;
		case WRITE:
      ret = cvm_write(ct->sbox, (int)a0, (char*)comp_to_mon(a1, ct->sbox), (size_t)a2);
			break;
		case OPEN:
//			ret = open(comp_to_mon(a0, ct->sbox), a1, a2);
      ret = cvm_open(ct->sbox, (char*)comp_to_mon(a0, ct->sbox), (int)a1, 0666);
			break;
		case LSEEK:
//			printf("lseek set %d %d %d\n", a0, a1, a2);
      ret = cvm_lseek(ct->sbox, a0, a1, a2);
//			printf("lseek ret = %d\n", ret);
			break;

		case 813:
			ret = errno;
//			perror("syscall:");
			break;

		case 814:
			ret = fcntl(a0, a1, comp_to_mon(a3, ct->sbox));
			break;


		default:
			printf("unknown t5 %ld\n", t5);
			while(1);
	}

#if 0
//	if(t5 != 1 && debug_calls)
	if (( tid == 2 && t5 !=1) && debug_calls)
		printf("OUT: %p: %lx %lx %lx %lx %lx %lx %lx %lx, %d \n", getSP(), a0, a1, a2, a3, a4, a5, a6, a7, t5);
#endif


	if(getTP() != ct->m_tp) {
		printf("TP has changed %p %p\n", getTP(), ct->m_tp);
	}

	mv_tp((unsigned long)ct->c_tp);

	return ret;
}


