#ifndef TFORK_H
#define TFORK_H

#include "common/list.h"
#include "image/image.pb-c.h"

struct c_thread;

#define MAX_CVMS	200

int tfork(void *, void *, int);

struct cvm_tmplt_ctx
{
    void *s0;
};


struct vm_map_entry {
    struct list_head list;

    VmaEntry e;
};
typedef struct vm_map_entry vm_map_entry;

struct vm_map_entry_list {
  struct list_head h;
  int nr;
};
typedef struct vm_map_entry_list vm_map_entry_list;

extern struct cvm_tmplt_ctx cvm_ctx[MAX_CVMS];
extern int cvm_snapshot_fd[MAX_CVMS];

void restore_from_template(int cid);
void notify_other_thread_save(struct c_thread *cur_thread);
void save_cur_thread_and_exit(int cid, struct c_thread *cur_thread);

#endif
