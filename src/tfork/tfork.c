#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include <tfork.h>

const int TFORK_FAILED = MAP_FAILED;
const static int tfork_syscall_num = 577;

int tfork(void *src_addr, void *dst_addr, int len)
{
    return syscall(tfork_syscall_num, src_addr, dst_addr, len);
}

int checkpoint(void *src_addr, int len, char *filepath)
{
    // todo, no-tested
    int fd = open(filepath, O_RDWR + O_CREAT);
    for (unsigned int *src = src_addr; src < src_addr + len; ++src)
    {
        write(fd, src, sizeof(unsigned int));
    }
    close(fd);
}

int resume(void *dst_addr, char *filepath)
{
    // todo
}