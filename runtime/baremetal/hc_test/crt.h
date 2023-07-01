#define START	"_start"

void _start(void)
{
    __asm__ volatile (
        ".weak __global_pointer$\n"
        ".hidden __global_pointer$\n"
        ".option push\n"
        ".option norelax\n\t"
        "lla gp, __global_pointer$\n"
        ".option pop\n\t"
        "mv a0, sp\n"
        ".weak _DYNAMIC\n"
        ".hidden _DYNAMIC\n\t"
        "lla a1, _DYNAMIC\n\t"
        "andi sp, sp, -16\n\t"
        "tail main"
    );
    // never reach
}

