#ifndef _FS_TYPE_H_
#define _FS_TYPE_H_

#include <stdint.h>
#include <sys/types.h>

#include <sys/stat.h>

typedef struct s_box s_box;

// unikraft
#define FDTABLE_MAX_FILES 64

#define UK_FREAD 0x00000001
#define UK_FWRITE 0x00000002

// runtime maintained
struct shared_fd {
  int sysfd;
  unsigned ref_count;
};
typedef struct shared_fd shared_fd;
extern struct shared_fd realfd_table[FDTABLE_MAX_FILES * 10];

// called by monitor_init
int init_realfd_table();
shared_fd *vfscore_sharedfd_init(int realfd);

// virtualized file
struct vfscore_file {
  struct shared_fd *sharedfd; // wrapper for sysfd with refer count
  int f_flags;            // virtual file open flag
  off_t f_offset;         // virtual file current offset
};
typedef struct vfscore_file vfscore_file;

// virtualized fdtable
struct fdtable {
  struct vfscore_file files[FDTABLE_MAX_FILES];
};
typedef struct fdtable fdtable;

int fdtable_init(fdtable *ft);
int fdtable_fork(fdtable *old_ft, fdtable *new_ft);

int vfscore_allocfd(fdtable *ft);
int init_stdio(struct fdtable *ft);

struct carrier_stat {
  uint16_t st_dev;
  uint16_t st_ino;
  uint32_t st_mode;
  uint16_t st_nlink;
  uint16_t st_uid;
  uint16_t st_gid;
  uint16_t st_rdev;
  uint64_t st_size;
  struct timespec st_atim;
  struct timespec st_mtim;
  struct timespec st_ctim;
  uint64_t st_blksize;
  uint64_t st_blocks;
  uint64_t st_spare4[2];
};

int cvm_open(s_box *cvm, char *path, int flags, mode_t mode);
int cvm_write(s_box *cvm, int fd, const char *buf, size_t len);
int cvm_read(s_box *cvm, int fd, char *buf, size_t len);
int cvm_lseek(s_box *cvm, int fd, off_t offset, int whence);
int cvm_stat(s_box *cvm, const char *restrict pathname,
             struct carrier_stat *restrict carrier_stat);
int cvm_close(s_box *cvm, int fd);

#endif // _FS_TYPE_H_
