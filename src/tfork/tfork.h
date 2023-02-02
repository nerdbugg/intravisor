int tfork(void *, void *, int);

struct cvm_tmplt_ctx
{
    void *sp;
    void *s0;
    void *ra;
    void *pc;
    void *c_tp;
};