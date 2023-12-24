#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>

#include "monitor.h"
#include "tfork.h"
#include "common/log.h"
#include "common/utils.h"
#include "common/profiler.h"
#include "cvm/init.h"
#include "hostcalls/host_syscall_callbacs.h"
#include "hostcalls/hostcall_tracer.h"
#include "hostcalls/fs/fd.h"

struct s_box	cvms[MAX_CVMS];
int send_req, receive_resp;

//default config
int timers = 0;
int debug_calls = 0;
//
pthread_mutex_t print_lock;

extern uint64_t starttime;
// extern host_syscall_handler_adv(char *, void * __capability pcc, void * __capability ddc, void * __capability pcc2);
// extern host_syscall_handler_prb(char *name, void *, void *, void *);
extern void tp_write();
extern void ret_from_cinv2();

extern const int TFORK_FAILED;

#if SIM
extern void __inline__ cinv(void *, void *, void *, void *, void *, void *, void *, void *);
#else
extern void cinv(void *, void *, void*);
#endif

void parse_cmdline(char *argv[], const char *disk_img, const char *runtime_so, char **yaml_cfg, int *skip_argc) {
	for (++argv; *argv; ++argv)
	{
		if (strcmp("-h", *argv) == 0 || strcmp("--help", *argv) == 0)
		{
			printf("CARRIE -- a virtualisation platform for CHERI\n\t <monitor> [-hdt] --args /path/to/app [app args] \n");
			printf("\t-h --help\tshow this help and exit\n");
			printf("\t-d --disk\tpath to disk image. Default is %s\n", disk_img);
			printf("\t-r --runtime\tpath to runtime so. Default is %s\n", runtime_so);
			printf("\t-y --yaml\tpath to yaml config. Default is %s\n", yaml_cfg);
			printf("\t-c --debug_calls\t trace hostcalls at the host side, default is %d\n", debug_calls);
			printf("\t-t --timer\tenable oneshot timer threads, default: %d\n", timers);
			exit(0);
		}
		else if (strcmp("-y", *argv) == 0 || strcmp("--yaml", *argv) == 0)
		{
			*yaml_cfg = *++argv;
			dlog("Using yaml.cfg = %s\n", *yaml_cfg);

			break;
		}
		else if (strcmp("-d", *argv) == 0 || strcmp("--disk", *argv) == 0)
		{
		  skip_argc+=2;
			disk_img = *++argv;
		}
		else if (strcmp("-t", *argv) == 0 || strcmp("--timer", *argv) == 0)
		{
		  skip_argc+=2;
			timers = atoi(*++argv);
		}
		else if (strcmp("-c", *argv) == 0 || strcmp("--debug_calls", *argv) == 0)
		{
		  skip_argc+=2;
			debug_calls = atoi(*++argv);
		}
		else if (strcmp("-a", *argv) == 0 || strcmp("--args", *argv) == 0)
		{

			  break; //argv now points to the beginning of args
		}
	}
}

int monitor_init() {
	if (pthread_mutex_init(&print_lock, NULL) != 0) {
		printf("\n mutex init failed\n");
		return 1;
	}
	memset(cvms, 0, sizeof(cvms));
  // init monitor fd table
  init_realfd_table();
	init_cap_files_store();
	// init callback/hostcall trace file
	init_hc_tracer();
	// init callback manager store
	init_cbs(); // callbacks
	// init default hostcall handlers
/*** 		we generate and seal intravisor caps. cVMs use them later as hostcall/syscall handler ***/

	void *__capability ddc_cap = cheri_getdefault();
	void *__capability pcc_cap = cheri_getpcc();
	void *__capability pcc_cap2 = cheri_getpcc();
	pcc_cap = cheri_setaddress(pcc_cap, (unsigned long) tp_write);

//	printf("ret_from_cinv2 = %ld\n", ret_from_cinv2);
	pcc_cap2 = cheri_setaddress(pcc_cap2, (unsigned long) ret_from_cinv2);

	void * __capability sealcap;
	size_t sealcap_size;

	sealcap_size = sizeof(sealcap);
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0) {
		printf("sysctlbyname(security.cheri.sealcap)\n");while(1);
	}

	void * __capability sealed_pcc = cheri_seal(pcc_cap, sealcap);   // tp_write
	void * __capability sealed_pcc2 = cheri_seal(pcc_cap2, sealcap); // ret_from_cinv2
	void * __capability sealed_ddc = cheri_seal(ddc_cap, sealcap);   // default (?)

	host_syscall_handler_adv("monitor", sealed_pcc, sealed_ddc, sealed_pcc2);
	return 0;
}

int build_capfile(struct capfile *f) {
	if(f->addr) {
		printf("capfiles with pre-defined addresses are not supported\n");
	}

	void *ptr = malloc (f->size);
	if(!ptr) {
		printf("cannot alloc %d bytes for %s key\n", f->size, f->name);
		return 0;
	}

	memset(ptr, 0, f->size);

	//we support only text here
	if(f->data) {
		snprintf(ptr, f->size, "%s", f->data);
	}

	host_cap_file_adv(ptr, f->size, f->name);
}

int link_cvm(struct cvm *flist) {
	for (struct cvm *f = flist; f; f = f->next) {
		if(!f->cb_in) {
			continue;
		}

		for (struct cvm *n = flist; n; n = n->next) {
//todo: instead of runtime name we should use name. here in all other relevant places
			if (strcmp(f->cb_in, n->runtime) == 0) {
				cvms[f->isol.base / 0x10000000].inner=&cvms[n->isol.base / 0x10000000];
				printf("%s[%d] is inner for %s[%d]\n",  cvms[f->isol.base / 0x10000000].threads[0].cb_in, n->isol.base / 0x10000000, 
														f->runtime, f->isol.base / 0x10000000);
			}
		}
	}
}

int monitor_main(int argc, char *argv[]) {
//	printf("hello world %d %s\n", argc, argv[1]);
	starttime = get_ms_timestamp();
	char *disk_img = "./disk.img";
	char *yaml_cfg = 0;
	char *runtime_so = "libcarrie.so";
	int skip_argc = 1;

	if (monitor_init() != 0) {
		printf("\n monitor init failed\n");
		return 1;
	}

	parse_cmdline(argv, disk_img, runtime_so, &yaml_cfg, &skip_argc);

	if(yaml_cfg == 0) {
		// doesn't have -y *.yaml
		// default_cvm(runtime_so, disk_img, argc - skip_argc, argv);
		printf("usage: monitor -y config.yaml\n"); exit(1);
	}

  profiler_begin(&(profilers[E2E]));
  profiler_begin(&(profilers[PARSE_CONFIG]));

	struct parser_state *state = run_yaml_scenario(yaml_cfg);
	if(state == 0) {
		printf("yaml is corrupted, die\n"); exit(1);
	}
	dlog("state = %p\n", state);
	dlog("state->clist = %p\n", state->clist);
	dlog("[%3d ms]: finish parse yaml\n", gettime());

  profiler_end(&(profilers[PARSE_CONFIG]));

	for (struct capfile *f = state->clist; f; f = f->next) {
		// printf("capfile: name=%s, data='%s', size=0x%lx, addr=0x%lx \n", f->name, f->data, f->size, f->addr);
		build_capfile(f);
	}

	// printf("***************** Link Inner<-->Outer ***************\n");
	// link_cvm(state->flist);
	
	for (struct cvm *f = state->flist; f; f = f->next) {
    if(f->resume == true) {
      // NOTE: regard current boot as resume 
      // asume template has been initialized, no strict guard here
      profiler_begin(&(profilers[SANDBOX_RESUME]));
    } else {
      profiler_begin(&(profilers[SANDBOX_INIT]));
    }

		create_and_start_cvm(f);
	}
	
	// wait completion
	for (int i = 0; i < MAX_CVMS; i++) {
		struct c_thread *ct = cvms[i].threads;

    if(ct[0].tid==NULL) {
      continue;
    }

		void *cret;
		pthread_join(ct[0].tid, &cret);
	}

  profiler_end(&(profilers[WORKLOAD_EXECUTE]));
  profiler_end(&(profilers[WORKLOAD_RESUME]));
  profiler_end(&(profilers[WORKLOAD_TOTAL]));
  profiler_end(&(profilers[E2E]));
  profiler_dump(true);

	printf("all cvm exit, monitor exit.\n");
	return 0;
}

int main(int argc, char *argv[]) { 
	pid_t pid;
	int req_pipe[2];
	int resp_pipe[2];

	if (pipe(req_pipe) != 0) {
		printf("pipe failed\n");
		exit(1);
	};

	if (pipe(resp_pipe) != 0) {
		printf("pipe failed\n");
		exit(1);
	};

	pid = fork();
	if (pid == 0) {
		send_req = req_pipe[1];
		receive_resp = resp_pipe[0];
		monitor_main(argc, argv);
		close(req_pipe[0]);
	} else {
		daemon_main(pid, req_pipe[0], resp_pipe[1]);
	}
}
