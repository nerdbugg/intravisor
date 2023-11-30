#include <cheri/cheri.h>
#include <cheri/cheric.h>

extern uint64_t starttime;
uint64_t gettime();
uint64_t get_ms_timestamp();

int host_purge_cap(void *location);
int host_reg_cap(void *ptr,long size,void *location);
int create_console(int cid);

void check_canaries(unsigned long *begin,long size,long magic);
void place_canaries(unsigned long *begin,long size,long magic);

#ifndef SIM
void *__capability datacap_create(void *sandbox_base,void *sandbox_end);
void *__capability pure_codecap_create(void *sandbox_base,void *sandbox_end);
void *__capability codecap_create(void *sandbox_base,void *sandbox_end);
#endif

unsigned long comp_to_mon_force(unsigned long addr,struct s_box *sbox);
unsigned long comp_to_mon(unsigned long addr,struct s_box *sbox);
unsigned long mon_to_comp(unsigned long addr,struct s_box *sbox);
int sboxptr_to_cid(struct s_box *p);
