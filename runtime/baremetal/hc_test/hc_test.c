#include "hostcalls.h"

int main() {
	char buf[32];
	char cap[16]; //place to store the capability
	long size;

	host_print("Hello World!\n", 13);
  host_write(1, "Called host_write\n", 18);

	host_cap_prb("test1", cap, &size);
	copy_from_cap(buf, cap, 32);
	host_print(buf, 32);

	host_save();

	host_print("Hello World! After Save\n", 24);
  host_write(1, "Called host_write. After Save\n", 30);

	// never reached
	return 0;
}

