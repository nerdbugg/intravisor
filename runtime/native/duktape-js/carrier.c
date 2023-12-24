#include "carrier.h"

#define SAVE 115
#define GET_ARG 116

extern unsigned long __hostcall(unsigned long call_num, unsigned long arg1,
                                unsigned long arg2, unsigned long arg3);

void generate_snapshot() { __hostcall(SAVE, 0, 0, 0); }

int get_arg(char *buf, size_t len) {
  return __hostcall(GET_ARG, (unsigned long)buf, len, 0);
}
