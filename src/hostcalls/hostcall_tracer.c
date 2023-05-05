#include <stdio.h>

FILE* hc_trace_f;

void init_hc_tracer()
{
    hc_trace_f = fopen("./hc_trace", "w+");
    
}