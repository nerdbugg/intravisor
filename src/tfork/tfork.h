#ifndef TFORK_H
#define TFORK_H

struct c_thread;

#define MAX_CVMS	200

int tfork(void *, void *, int);

struct cvm_tmplt_ctx
{
    void *s0;
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

void load_all_thread(int cid);
void notify_other_thread_save(struct c_thread *cur_thread);
void save_cur_thread_and_exit(int cid, struct c_thread *cur_thread);

#endif
