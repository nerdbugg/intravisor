#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "hostcalls/fs/fd.h"
#include "monitor.h"

realfd realfd_table[FDTABLE_MAX_FILES * 10];

// called by monitor_init
int init_realfd_table() {
  realfd_table[0].sysfd = 0;
  realfd_table[0].ref_count = 1;

  realfd_table[1].sysfd = 1;
  realfd_table[1].ref_count = 1;

  realfd_table[2].sysfd = 2;
  realfd_table[2].ref_count = 1;
  return 0;
}

// called by cvm init
int fdtable_init(fdtable *ft) {
  memset(ft, 0, sizeof(struct fdtable));
  return init_stdio(ft);
}

realfd *vfscore_realfd_init(int sysfd) {
  int i = 3;
  for (; i < FDTABLE_MAX_FILES * 10; i++) {
    if (realfd_table[i].ref_count == 0) {
      break;
    }
  }

  if (i == FDTABLE_MAX_FILES * 10) {
    return NULL;
  }

  realfd_table[i].sysfd = sysfd;
  realfd_table[i].ref_count = 1;
  return &(realfd_table[i]);
}

static inline int vfscore_file_init(vfscore_file *file, realfd *rfd,
                                    int flags) {
  file->real_fd = rfd;
  file->f_flags = flags;
  file->f_offset = 0;
  return 0;
}

int init_stdio(struct fdtable *ft) {
  ft->files[0].f_flags = UK_FREAD;
  ft->files[0].real_fd = &realfd_table[0];

  ft->files[1].f_flags = UK_FWRITE;
  ft->files[1].real_fd = &realfd_table[1];

  ft->files[2].f_flags = UK_FWRITE;
  ft->files[2].real_fd = &realfd_table[2];

  return 0;
}

int vfscore_allocfd(fdtable *ft) {
  int i = 3;
  for (; i < FDTABLE_MAX_FILES; i++) {
    if (ft->files[i].f_flags != 0) {
      break;
    }
  }

  if (i < FDTABLE_MAX_FILES)
    return i;
  else
    return -1;
}

int cvm_open(s_box *cvm, char *path, int flags, mode_t mode) {
  fdtable *ft = &(cvm->fdtable);

  // TODO: check path feasibility

  int sysfd = open(path, flags, mode);
  if (sysfd < 0) {
    return sysfd;
  }

  realfd *rfd = vfscore_realfd_init(sysfd);
  if (rfd == NULL) {
    return ENOSYS;
  }

  int fd = vfscore_allocfd(ft);
  if (fd < 0) {
    return ENOSYS;
  }

  // initialize fd info in fdtable
  // TODO: check flags
  vfscore_file_init(&(ft->files[fd]), rfd, flags);

  return fd;
}

// buf show be global address
int cvm_write(s_box *cvm, int fd, const char *buf, size_t len) {
  if (fd > FDTABLE_MAX_FILES)
    return EBADF;

  fdtable *ft = &(cvm->fdtable);
  vfscore_file *file = &(ft->files[fd]);

  // check read write feasibility
  if ((file->f_flags & UK_FWRITE) == 0)
    return EBADF;

  int sysfd = file->real_fd->sysfd;
  return write(sysfd, buf, len);
}

int cvm_read(s_box *cvm, int fd, char *buf, size_t len) {
  if (fd > FDTABLE_MAX_FILES)
    return EBADF;

  fdtable *ft = &(cvm->fdtable);
  vfscore_file *file = &(ft->files[fd]);

  if ((file->f_flags & UK_FREAD) == 0)
    return EBADF;

  int sysfd = file->real_fd->sysfd;
  return read(fd, buf, len);
}
