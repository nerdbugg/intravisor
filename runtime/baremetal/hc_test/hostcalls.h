extern unsigned long local_cap_store;

// note: defined in tramps.S
extern unsigned long c_out_2(unsigned long call_num, unsigned long arg1, unsigned long arg2);
extern unsigned long c_out_3(unsigned long call_num, unsigned long arg1, unsigned long arg2, unsigned long arg3);
extern unsigned long ret_from_monitor();
extern void copy_from_cap(void *dst, void *src_cap_location, int len);

// hostcalls
int host_print(char *ptr, int size);
int host_write(int fd, const char* buf, int size);
int host_cap_prb(char *key, void *location, long *size);
void host_exit();
void host_save();

