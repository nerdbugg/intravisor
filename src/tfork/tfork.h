#ifndef TFORK_H
#define TFORK_H

#include "monitor.h"

int tfork(void *, void *, int);
int checkpoint(void *, int, char *);

struct cvm_tmplt_ctx
{
    void *sp;
    void *s0; 
    void *ra;
    void *pc;
    void *c_tp;
};

struct map_entry {
    struct map_entry *next;

    unsigned long start, end;
    int prot;
};
typedef struct map_entry map_entry;

extern struct cvm_tmplt_ctx cvm_ctx[MAX_CVMS];
extern map_entry* cvm_map_entry_list[MAX_CVMS];
extern int cvm_snapshot_fd[MAX_CVMS];

#endif
