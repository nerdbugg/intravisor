#define START	_start

.section .sdata, "aw"
.text
.global  START
.type START,%function
START :

    .weak __global_pointer$
    .hidden __global_pointer$
    .option push
    .option norelax
    lla gp, __global_pointer$
    .option pop
    mv a0, sp
    .weak _DYNAMIC
    .hidden _DYNAMIC
    lla a1, _DYNAMIC
    andi sp, sp, -16
    tail main

