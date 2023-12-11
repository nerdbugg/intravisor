#include <sys/time.h>
#include <stdbool.h>

#define MAX_PROFILERS 16

struct profiler_t {
  struct timespec begin;
  struct timespec end;
  struct timespec elapsed;
  bool enabled;
};
typedef struct profiler_t profiler_t;

enum event_type {
  PARSE_CONFIG,
  SANDBOX_INIT,
  WORKLOAD_TOTAL,
  WORKLOAD_PREPARE,
  SNAPSHOT_GEN,
  WORKLOAD_EXECUTE,
  SANDBOX_RESUME,
  WORKLOAD_RESUME,
  MMAP_RESTORE,
  MPROTECT_RESTORE,
  E2E,
  MAX_PROFILER_NUM
};

extern profiler_t profilers[MAX_PROFILER_NUM];



void profiler_begin(profiler_t *p);
void profiler_end(profiler_t *p);
void profiler_dump();
