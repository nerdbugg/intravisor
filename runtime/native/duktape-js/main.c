#include <stdio.h>
#include <string.h>

#include "duk_config.h"
#include "duktape.h"

static duk_ret_t native_print(duk_context *ctx) {
  duk_push_string(ctx, " ");
  duk_insert(ctx, 0);
  duk_join(ctx, duk_get_top(ctx) - 1);
  printf("%s\n", duk_to_string(ctx, -1));
  return 0;
}

int get_file_content(char *path, char *buf, int len) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    return -1;
  }

  int res = fread(buf, sizeof(char), len, file);
  buf[res] = '\0';

  fclose(file);

  return res;
}

void eval_string(duk_context *ctx, const char *expr) {
  int rc = duk_peval_string(ctx, expr);
  if(rc != 0) {
    duk_safe_to_stacktrace(ctx, -1);
    const char *res = duk_get_string(ctx, -1);
    printf("%s\n", res ? res: "null");
  } else {
  }
  duk_pop(ctx);
}

void eval_code(duk_context *ctx, char *code, int len) {
  if (duk_peval_lstring(ctx, code, len) != 0) {
    duk_safe_to_stacktrace(ctx, -1);
    const char *res = duk_get_string(ctx, -1);
    printf("DUKTAPE ERROR: %s\n", res ? res : "null");
  }

  duk_pop(ctx);
}

int main(int argc, char *argv[]) {
  duk_context *ctx = NULL;
  int i;
  duk_int_t rc;
  char code[4*1024];

  ctx = duk_create_heap_default();
  if (ctx == NULL) {
    printf("context is null!\n");
    return 1;
  }

  duk_push_c_function(ctx, native_print, DUK_VARARGS);
  duk_put_global_string(ctx, "print");
  eval_string(ctx, "function hcall_return(arg) {/* do nothing */}");

  // init code
  if(argc<2) {
    printf("need args\n");
    return 1;
  }
  int len = get_file_content(argv[1], code, 4*1024);

  
  eval_code(ctx, code, len);

  return 0;
}
