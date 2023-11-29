#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

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
  int res = fread(buf, sizeof(char), end, file);
  printf("returned %d, readed \"%s\"\n", res, buf);
  assert(res==end);
  assert(strcmp(buf, "Hello\n")==0);

  printf("[5] fclose(file)\n");
  res = fclose(file);
  assert(res==0);

  // NOTE: ./textnew
  printf("[6] fwrite(file)\n");
  FILE *newfile = fopen("./text_new", "w+");
  char *str="World";
  res = fwrite(str, sizeof(char), strlen(str), newfile);
  assert(res==strlen("World"));
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
  printf("[workload] returned %d, errno is %d\n", res, errno);

  return 0;
}
