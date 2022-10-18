#include "crt.h"
#include "hostcalls.h"

#define MSG "hello world, let's read cap 'test1' \n"
extern syscall_write(int fd, char * buf, int len);

void hello_c() {
	char buf[32];
	char cap[16]; //place to store the capability
	long size;

	buf[0] = 'y';
	buf[1] = 'j';
	buf[2] = 'n';
	// syscall_write(1, buf + 0x20000000, 3);

	host_write(MSG, sizeof(MSG));

	host_cap_prb("test1", cap, &size);

	copy_from_cap(buf, cap, 32);

	host_write(buf, 32);

	host_exit();
}

