#pragma once

typedef struct _process
{
    struct _process* nextReadyProcess;
    struct _process* nextSiblingProcess;

    struct _process* pParent;
    struct _process* pChildren;

    char           name[MAXNAME];     /* Process name */
    char           startArgs[MAXARG]; /* Process arguments */
    void* context;           /* Process's current context */
    short          pid;               /* Process id (pid) */
    int            priority;
    int (*entryPoint)(void*);         /* The entry point that is called from launch */
    char* stack;
    unsigned int   stacksize;
    int            status;            /* READY, QUIT, BLOCKED, etc. */

  
    void* args;              /* argument passed to entryPoint */
    int   exitCode;          /* this process's exit code */
    int   waiting;           /* 1 if blocked in k_wait */
    short zombiePid;         /* child's pid ready to collect */
    int   zombieExitCode;    /* child's exit code */

} Process;
