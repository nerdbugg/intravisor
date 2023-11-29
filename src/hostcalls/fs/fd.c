#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "hostcalls/fs/fd.h"
#include "monitor.h"

shared_fd realfd_table[FDTABLE_MAX_FILES * 10];

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

shared_fd *vfscore_sharedfd_init(int sysfd) {
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

static inline int vfscore_file_init(vfscore_file *file, shared_fd *rfd,
                                    int flags) {
  file->sharedfd = rfd;
  file->f_flags = flags;
  file->f_offset = 0;
  return 0;
}

int init_stdio(struct fdtable *ft) {
  ft->files[0].f_flags = UK_FREAD;
  ft->files[0].sharedfd = &realfd_table[0];

  ft->files[1].f_flags = UK_FWRITE;
  ft->files[1].sharedfd = &realfd_table[1];

  ft->files[2].f_flags = UK_FWRITE;
  ft->files[2].sharedfd = &realfd_table[2];

  return 0;
}

int vfscore_allocfd(fdtable *ft) {
  int i = 3;
  for (; i < FDTABLE_MAX_FILES; i++) {
    if (ft->files[i].f_flags == 0) {
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
    return -ENOENT;
  }

  shared_fd *rfd = vfscore_sharedfd_init(sysfd);
  printf("[intravisor/fs] rfd = &realfd_table[%lu]\n", rfd - realfd_table);
  if (rfd == NULL) {
    return -ENOMEM;
  }

  int fd = vfscore_allocfd(ft);
  if (fd < 0) {
    return -ENOMEM;
  }

  // initialize fd info in fdtable
  int ukflags = UK_FREAD;
  if (flags & O_RDWR) {
    ukflags |= UK_FREAD | UK_FWRITE;
  } else if (flags & O_RDONLY) {
    ukflags |= UK_FREAD;
  } else if (flags & O_WRONLY) {
    ukflags |= UK_FWRITE;
  }
  vfscore_file_init(&(ft->files[fd]), rfd, ukflags);

  printf("[intravisor/fs] cvm_open(%p, %s, %d, %04o), sysfd = %d, fd = %d\n",
         cvm, path, flags, mode, sysfd, fd);

  return fd;
}

// buf should be global address
int cvm_write(s_box *cvm, int fd, const char *buf, size_t len) {
  // printf("[intravisor/fs] called cvm_write\n");

  if (fd > FDTABLE_MAX_FILES)
    return -EBADF;

  fdtable *ft = &(cvm->fdtable);
  vfscore_file *file = &(ft->files[fd]);

  // printf("[intravisor/fs] %s: file->f_flags = %d\n", __func__,
  // file->f_flags);

  // check read write feasibility
  if ((file->f_flags & UK_FWRITE) == 0) {
    // printf("[intravisor/fs] %s: write failed\n", __func__);
    return -EBADF;
  }

  int sysfd = file->sharedfd->sysfd;

  // skip stdio
  if (sysfd > 2) {
    // set offset
    lseek(sysfd, file->f_offset, SEEK_SET);
  }

  // NOTE: the return value does not contain errno?
  int res = write(sysfd, buf, len);
  // printf("[intravisor/fs] write syscall returned %d, errno is %d\n", res,
  // errno);
  if(res>0) {
    file->f_offset += res;
  }

  if (errno) {
    return -errno;
  } else {
    return res;
  }
}

int cvm_read(s_box *cvm, int fd, char *buf, size_t len) {
  if (fd > FDTABLE_MAX_FILES) {
    printf("[intravisor/fs] fd>FDTABLE_MAX_FILES\n");
    return -EBADF;
  }

  fdtable *ft = &(cvm->fdtable);
  vfscore_file *file = &(ft->files[fd]);

  if ((file->f_flags & UK_FREAD) == 0) {
    printf("[intravisor/fs] (file->f_flags & UK_FREAD) == 0\n");
    return -EBADF;
  }

  int sysfd = file->sharedfd->sysfd;

  // set offset
  lseek(sysfd, file->f_offset, SEEK_SET);

  int res = read(sysfd, buf, len);

  if(res>0) {
    file->f_offset += res;
  }

  if (errno) {
    return -errno;
  } else {
    return res;
  }
}

int cvm_lseek(s_box *cvm, int fd, off_t offset, int whence) {
  fdtable *ft = &(cvm->fdtable);
  vfscore_file *file = &(ft->files[fd]);
  if (file->sharedfd == NULL) {
    return -EBADF;
  }

  int res;
  switch (whence) {
  case SEEK_SET:
    file->f_offset = offset;
    res = offset;
    break;
  case SEEK_CUR:
    res = file->f_offset;
    break;
  case SEEK_END:
    res = lseek(file->sharedfd->sysfd, 0, SEEK_END);
    file->f_offset = res; // sync virtual file to real offset
    break;
  default:
    res = -EINVAL;
  }

  return res;
}

// TODO: provide cvm close here, and call it in hostcall
int cvm_close(s_box *cvm, int fd) {
  // skip stdio fd
  if (fd < 3) {
    return 0;
  }

  if (fd > FDTABLE_MAX_FILES) {
    printf("[intravisor/fs] fd>FDTABLE_MAX_FILES\n");
    return -EBADF;
  }

  fdtable *ft = &(cvm->fdtable);

  vfscore_file *file = &(ft->files[fd]);
  file->f_flags = 0; // free the vfscore_file

  shared_fd *sharedfd = file->sharedfd;
  sharedfd->ref_count -= 1;
  if (sharedfd->ref_count == 0) { // free the shared_fd
    printf("[intravisor/fs] shared_fd %p will be freed\n", sharedfd);

    int sysfd = file->sharedfd->sysfd;
    printf("[intravisor/fs] close(%d), sysfd = %d\n", fd, sysfd);
    close(sysfd);
  }

  return 0;
}

int cvm_dup(s_box *cvm, int fd) {
  fdtable *ft = &(cvm->fdtable);

  int newfd = vfscore_allocfd(ft);

  shared_fd *sharedfd = ft->files[fd].sharedfd;
  sharedfd->ref_count += 1; // shared, refcount += 1

  // init new fd with same meta
  ft->files[newfd].sharedfd = sharedfd;
  ft->files[newfd].f_flags = ft->files[fd].f_flags;
  ft->files[newfd].f_offset = ft->files[fd].f_offset;

  return newfd;
}
