int tfork(void *, void *, int);
int checkpoint(void *, int, char *);

struct cvm_tmplt_ctx
{
    void *sp;
    void *s0; 
    void *ra;
    void *pc;
    void *c_tp;
};