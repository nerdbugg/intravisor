#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>

int main(int argc, char *argv[]) {
  printf("Test printf operation\n");
  printf("int %d, size %zd, unsigned %u, char %c\n", 1, 1L, 1, '1');

  printf("Test file operation\n");

  printf("[1] fopen(noexist)\n");
  FILE *noexist = fopen("noexist", "r");
  if (noexist != NULL) {
    printf("- test failed\n");
    return 1;
  }

  // NOTE: ./text (Hello)
  printf("[2] fopen(file)\n");
  FILE *file = fopen("text", "r");
  if (file == NULL) {
    printf("- test failed\n");
    return 1;
  }

  printf("[3] fseek(file)\n");
  fseek(file, 0, SEEK_END);
  size_t end = ftell(file);
  if (end != 6) {
    printf("- test failed\n");
    printf("file size = %lu\n", end);
    return 1;
  }

  printf("[4] fread(file)\n");
  fseek(file, 0, SEEK_SET);
  char buf[16];
  size_t res = fread(buf, sizeof(char), end, file);
  printf("returned %ld, readed \"%s\"\n", res, buf);
  if(res!=end) {
    printf("fread ret: %ld, expected: %ld\n", res, end);
    return 1;
  }
  if(strcmp(buf, "Hello\n")!=0) {
    printf("fread buf: %s, expected: %s\n", buf, "Hello");
    return 1;
  }

  printf("[5] fclose(file)\n");
  res = fclose(file);
  if(res!=0) {
    printf("fclose ret: %ld, expected: %d\n", res, 0);
    return 1;
  }

  // NOTE: ./textnew
  printf("[6] fwrite(file)\n");
  FILE *newfile = fopen("./text_new", "w+");
  char *str="World";
  res = fwrite(str, sizeof(char), strlen(str), newfile);
  if(res!=strlen("World")) {
    printf("fwrite ret: %ld, expected: %ld\n", res, strlen("World"));
    return 1;
  }
  fclose(newfile);

  // NOTE: ./readonly
  printf("[7] fwrite failed\n");
  FILE *readonly = fopen("./readonly", "r");
  if(readonly==NULL) {
    printf("fopen failed\n");
    return 1;
  }

  res = fwrite(str, sizeof(char), strlen(str), newfile);
  printf("[workload] strerr of errno(%d) is: %s\n", errno, strerror(errno));
  printf("[workload] returned %ld, errno is %d\n", res, errno);


  printf("[8] stat\n");
  struct stat statbuf;
  printf("[workload] &statbuf = %p\n", &statbuf);
  int ret = stat("./readonly", &statbuf);
  if(ret!=0) {
    printf("stat failed\n");
    return 1;
  }
  if(S_ISREG(statbuf.st_mode)!=1) {
    printf("stat failed, S_ISREG() should be 1\n");
    printf("statbuf.st_mode = %d\n", statbuf.st_mode);
    return 1;
  }

  printf("[8] stat field\n");
  void* statbuf_end = (void*)&statbuf + sizeof(statbuf);
  printf("&(statbuf) = %p, sizeof(statbuf) = %ld\n", &(statbuf), sizeof(statbuf));
  printf("&(statbuf.st_dev) = %p\n", &(statbuf.st_dev));
  printf("&(statbuf.st_ino) = %p\n", &(statbuf.st_ino));
  printf("&(statbuf.st_mode) = %p\n", &(statbuf.st_mode));
  printf("&(statbuf.st_nlink) = %p\n", &(statbuf.st_nlink));
  printf("&(statbuf.st_uid) = %p\n", &(statbuf.st_uid));
  printf("&(statbuf.st_gid) = %p\n", &(statbuf.st_gid));
  printf("&(statbuf.st_rdev) = %p\n", &(statbuf.st_rdev));
  printf("&(statbuf.st_size) = %p\n", &(statbuf.st_size));
  printf("&(statbuf.st_atim) = %p\n", &(statbuf.st_atim));
  printf("&(statbuf.st_mtim) = %p\n", &(statbuf.st_mtim));
  printf("&(statbuf.st_ctim) = %p\n", &(statbuf.st_ctim));
  printf("&(statbuf.st_blksize) = %p\n", &(statbuf.st_blksize));
  printf("&(statbuf.st_blocks) = %p\n", &(statbuf.st_blocks));
  printf("&(statbuf.st_spare4) = %p\n", &(statbuf.st_spare4));
  printf("statbuf_end = %p\n", statbuf_end);

  printf("all test past!\n");

  return 0;
}
