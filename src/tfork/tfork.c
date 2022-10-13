#include <sys/mman.h>
#include <sys/syscall.h>

#include <tfork.h>

const int TFORK_FAILED = MAP_FAILED;
const static int tfork_syscall_num = 577;

int tfork(void *src_addr, void *dst_addr, int len)
{
    return syscall(tfork_syscall_num, src_addr, dst_addr, len);
}