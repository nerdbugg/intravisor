#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <assert.h>

#include "restore.h"
#include "common/log.h"
#include "common/list.h"
#include "common/utils.h"
#include "common/profiler.h"
#include "image/image.pb-c.h"
#include "tfork.h"

Image* image_deserialize_from_file(char *path) {
  FILE *image_file = fopen(path, "rb");
  
  fseek(image_file, 0, SEEK_END);
  size_t size = ftell(image_file);
  fseek(image_file, 0, SEEK_SET);

  uint8_t *buf = malloc(size);
  for(size_t l=0l;l<size;l+=fread(buf, sizeof(uint8_t), size, image_file));

  Image *image = image__unpack(NULL, size, buf);
  if(image==NULL) {
    printf("Image unpack error.");
    exit(1);
  }

  free(buf);
  fclose(image_file);
  return image;
}

void restore_cvm_region_from_snapshot(struct s_box *cvm, char* snapshot_path, struct s_box *t_cvm) {
  dlog("[debug] restore cvm using snapshot path: %s\n", snapshot_path);
  profiler_begin(&(profilers[MMAP_RESTORE]));

  char name_buf[128];

  char *page_path = name_buf;
  sprintf(page_path, "%s/pages.img", snapshot_path);
  FILE *page_file = fopen(page_path, "rb");
  int page_fd = fileno(page_file);

  fseek(page_file, 0, SEEK_END);
  size_t page_file_size = ftell(page_file);
  fseek(page_file, 0, SEEK_SET);

  dlog("[debug/restore] opened page file\n");

  char *image_path = name_buf;
  sprintf(image_path, "%s/image.img", snapshot_path);
  Image* image = image_deserialize_from_file(image_path);
  MmStruct *mm_struct = image->meminfo;

  dlog("[debug/restore] Image->meminfo->size = 0x%lx, page_size = 0x%lx\n", 
         mm_struct->size, page_file_size);

#ifndef MMAP_COMBINE
  for(int i=0;i<mm_struct->n_vma_entries;i++) {
    VmaEntry *vma_entry = mm_struct->vma_entries[i];

    void* map_start = (void*)(vma_entry->start - (unsigned long)t_cvm->cmp_begin + (unsigned long)cvm->cmp_begin);
    size_t map_size = vma_entry->end - vma_entry->start;

    dlog("[debug/restore] mmap(%p, 0x%lx, %d, MAP_PRIVATE|MAP_FIXED, %d, 0x%lx)\n", 
         map_start, map_size, vma_entry->prot, page_fd, vma_entry->pgoff);
    void *res = mmap(map_start, map_size, vma_entry->prot, MAP_PRIVATE|MAP_FIXED, page_fd, vma_entry->pgoff);
    if(res==MAP_FAILED) {
      printf("Image mmap failed.");
      exit(1);
    }
  }
  profiler_end(&(profilers[MMAP_RESTORE]));
#else
  VmaEntry *first_entry = mm_struct->vma_entries[0];

  void* map_start = (void*)first_entry->start-t_cvm->cmp_begin+cvm->cmp_begin;
  size_t map_size = first_entry->end-first_entry->start;
  size_t map_file_off = 0l;
  // iterate from 1, 0 is the last
  for(int i=1;i<mm_struct->n_vma_entries;i++) {
    VmaEntry *last_entry = mm_struct->vma_entries[i-1];
    VmaEntry *vma_entry = mm_struct->vma_entries[i];

    unsigned long start = vma_entry->start - t_cvm->cmp_begin + cvm->cmp_begin;
    size_t cur_entry_size = vma_entry->end - vma_entry->start;
    
    if(vma_entry->start == last_entry->end) {
      map_size += cur_entry_size;
    } else {
      dlog("[debug/restore] mmap(%p, 0x%lx, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, %d, 0x%lx)\n", 
           map_start, map_size, page_fd, map_file_off);
      void* res = mmap(map_start, map_size, PROT_READ|PROT_WRITE|PROT_EXEC,
                       MAP_PRIVATE|MAP_FIXED, page_fd, map_file_off);
      assert(res != MAP_FAILED);
      map_file_off += map_size;

      map_start = (void*)start;
      map_size = cur_entry_size;
    }
  }
  dlog("[debug/restore] mmap(%p, 0x%lx, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, %d, 0x%lx)\n", 
        map_start, map_size, page_fd, map_file_off);
  void* res = mmap(map_start, map_size, PROT_READ|PROT_WRITE, 
                    MAP_PRIVATE|MAP_FIXED, page_fd, map_file_off);
  assert(res!=MAP_FAILED);
  profiler_end(&(profilers[MMAP_RESTORE]));

  profiler_begin(&(profilers[MPROTECT_RESTORE]));
  for (int i=0; i<mm_struct->n_vma_entries; i++) {
    VmaEntry *entry = mm_struct->vma_entries[i];

    unsigned long map_start = entry->start-t_cvm->cmp_begin+cvm->cmp_begin;
    size_t map_size = entry->end - entry->start;
    
    dlog("[debug/restore] mprotect(%p, 0x%lx, %d)\n", (void*)map_start, map_size, entry->prot);
    int ret = mprotect((void*)map_start, map_size, entry->prot);
    if(ret==-1) {
      perror("mprotect: ");
      while (1) { }
    }
    // assert(ret != -1);
  }
  profiler_end(&(profilers[MPROTECT_RESTORE]));
#endif /* ifndef MACRO */
}

void restore_cvm_region(struct s_box *cvm, struct s_box *t_cvm) {
#ifndef TFORK
  dlog("prepare restore memory layout using template snapshot\n");
  int t_cid = t_cvm->cid;

  restore_cvm_region_from_snapshot(cvm, cvm->snapshot_path, t_cvm);

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

