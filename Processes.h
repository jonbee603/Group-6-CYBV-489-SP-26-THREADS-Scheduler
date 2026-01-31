#pragma once

typedef struct _process
{
	struct _process* nextReadyProcess;
	struct _process* nextSiblingProcess;

	struct _process* pParent;
	struct _process* pChildren;

	char           name[MAXNAME];        /* Process name */
	char           startArgs[MAXARG];    /* Process arguments */
	void* context;              /* Process's current context */
	short          pid;                  /* Process id (pid) */
	int            priority;			 /* Process can have priority 0-5, 5 being highest priority */
	int (*entryPoint) (void*);           /* The entry point that is called from launch */
	char* stack;				 /* For allocating stack memory */
	unsigned int   stacksize;			 /* Length/size of the stack */
	int            status;               /* READY, QUIT, BLOCKED, etc. */
	int			   processRunTime;       /* Total time process has run */
	void* args;              /* argument passed to entryPoint */
	int            exitCode;          /* this process's exit code */
	int            waiting;           /* 1 if blocked in k_wait */
	short          zombiePid;         /* child's pid ready to collect */
	int            zombieExitCode;    /* child's exit code */
} Process;
