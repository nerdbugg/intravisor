#include "monitor.h"
#include "tfork/tfork.h"

extern unsigned long TFORK_FAILED;

int init_pthread_stack(struct s_box *cvm);
void restore_cvm_region(struct s_box *cvm, struct s_box *t_cvm);
