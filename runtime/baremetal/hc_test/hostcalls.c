#include "hostcalls.h"
// local store for capabilitites, relative address usualy provided via AUX

// note: used in trampoline code to issue hostcall
// in hybrid mode, the real address is computed relative to ddc
// in pure mode, we need runtime relocation to get real address
// (dirty hack:specify a hard coded length of array to distinguish it from other data reloc)
unsigned long local_cap_store = 0xe001000;

int host_write(char *ptr, int size) {
	int tmp = 1;
	return c_out_2(tmp, (unsigned long)ptr, size);
}

void host_exit() {
	int tmp = 13;
	c_out_2(tmp, 0, 0);
}

int host_cap_prb(char *key, void *location, long *size) {
	int tmp = 406;
	return c_out_3(tmp, (unsigned long)key, (unsigned long)location, (unsigned long)size);
}

