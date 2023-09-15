#include "hostcalls.h"

int main() {
	char buf[32];
	char cap[16]; //place to store the capability
	long size;

	host_write("Hello World!\n", 13);

	host_cap_prb("test1", cap, &size);
	copy_from_cap(buf, cap, 32);
	host_write(buf, 32);

	host_save();

	host_write("Hello World! After Save\n", 24);

	// never reached
	return 0;
}

