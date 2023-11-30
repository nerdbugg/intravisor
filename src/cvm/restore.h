#include "monitor.h"
#include "tfork/tfork.h"

extern unsigned long TFORK_FAILED;

void restore_cvm_region(struct s_box *cvm, struct s_box *t_cvm);

