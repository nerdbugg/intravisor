#ifndef HOSTCALL_TRACER_H
#define HOSTCALL_TRACER_H

#include <stdio.h>


extern FILE* hc_trace_f;


#ifdef DEBUG
#define hostcall_trace(...) do {\
        fprintf(hc_trace_f , __VA_ARGS__); \
        fflush(hc_trace_f);\
}while(0)

#else // DEBUG
#define hostcall_trace(...) while(0) printf(__VA_ARGS__)
#endif // DEBUG


void init_hc_tracer();
// add close file function?

#endif HOSTCALL_TRACER_H
