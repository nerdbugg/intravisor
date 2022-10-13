@RO dir /intravisor/monitor_src
b cinv
start
c
b *0x200012C4
c
file libhello_debug.so
layout src
b hello_c
c

delete 1 2 3