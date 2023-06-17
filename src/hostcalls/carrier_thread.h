#include "monitor.h"

// used in host_make_call
void *c_thread_body(void *carg);

struct c_thread *get_cur_thread();
void destroy_carrie_thread(struct c_thread *ct);

#ifdef LKL
long create_carrie_thread(struct c_thread *ct, void *f, void *arg);
#endif

