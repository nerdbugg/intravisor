#include "restore.h"
#include "common/log.h"

void restore_cvm_region(struct s_box *cvm, struct s_box *t_cvm) {
#ifndef TFORK
  dlog("prepare restore memory layout using template snapshot\n");
  map_entry *map_entry_list = cvm_map_entry_list[t_cid];
  assert(map_entry_list != NULL);
  int fd = cvm_snapshot_fd[t_cid];
  assert(fd > 0);

  map_entry *last = NULL;
  size_t map_size = 0;
  unsigned long map_start = NULL;
  unsigned long file_offset = 0l;
  map_entry *p = map_entry_list;
  while (p) {
    unsigned long old_begin = cvms[t_cid].cmp_begin;
    unsigned long new_begin = cvm->cmp_begin;
    size_t size = p->end - p->start;
    unsigned long start = p->start - old_begin + new_begin;

    if (last == NULL || p->start == last->end) {
      if (map_start == NULL) {
        map_start = start;
      }
      map_size += size;
    } else {
      // note: first mmap RWX, then using mprotect to restore p->prot
      void *res = mmap(map_start, map_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE, fd, file_offset);
      assert(res != MAP_FAILED);
      file_offset += map_size;

      map_size = size;
      map_start = start;
    }
    last = p;
    p = p->next;
  }
  // note: the last iterattion
  if (last != NULL) {
    void *res = mmap(map_start, map_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE, fd, file_offset);
    assert(res != MAP_FAILED);
  }

  // note: using mprotect to restore permissions
  p = map_entry_list;
  while (p) {
    unsigned long old_begin = cvms[t_cid].cmp_begin;
    unsigned long new_begin = cvm->cmp_begin;
    size_t size = p->end - p->start;
    unsigned long start = p->start - old_begin + new_begin;

    int ret = mprotect(start, size, p->prot);
    assert(ret != -1);

    p = p->next;
  }
  dlog("complete snapshot restoration\n");
#else
  dlog("prepare to invoke tfork syscall, src_addr=%p, dst_addr=%p, len=%lu\n",
       (void *)t_cvm->cmp_begin, (void *)cvm->cmp_begin, cvm->box_size);
  if (tfork((void*)t_cvm->cmp_begin, (void*)cvm->cmp_begin, cvm->box_size) == TFORK_FAILED) {
    printf("tfork FAILED\n");
    exit(1);
  }
  dlog("tfork complete\n");
#endif
}

// When init template cvm, we must make sure stack memory is accessable by using mmap.
int init_pthread_stack(struct s_box *cvm)
{
    struct c_thread *ct = &cvm->threads[0];
    void* ret = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    else {
        dlog("[cVM STACKs] = [%p -- %lx]\n", ct->stack, (unsigned long)ct->stack + ct->stack_size);
    }

    /* Remove temporarily.The anonymous region is zero-filled*/
    // memset(ct->stack, 0, ct->stack_size);

    place_canaries(ct->stack, ct->stack_size, 0xabbacaca);
    check_canaries(ct->stack, ct->stack_size, 0xabbacaca);
    return 0;
}

