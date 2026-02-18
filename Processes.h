/*********************************************************************************
		Processes.h Final Implementation for the THREADS-Scheduler Project

					CYBV 489 - SP 26: Professor Li Xu
		   Group 6: Lexi Lamaide, Colin Martin, Jonathan Bergeron
**********************************************************************************/
#pragma once

typedef struct _process
{
	struct _process* nextReadyProcess;
	struct _process* nextSiblingProcess;
	struct _process* nextZombieProcess;

	struct _process* pParent;
	struct _process* pChildren;
	struct _process* zombieChildren;				 /* Linked list of zombies for this process's children */
	struct _process* zombieTail;

	char           name[MAXNAME];        /* Process name */
	char           startArgs[MAXARG];    /* Process arguments */
	void* context;						 /* Process's current context */
	short          pid;                  /* Process id (pid) */
	int            priority;			 /* Process can have priority 0-5, 5 being highest priority */
	int (*entryPoint) (void*);           /* The entry point that is called from launch */
	char* stack;						 /* For allocating stack memory */
	unsigned int   stacksize;			 /* Length/size of the stack */
	int            status;               /* READY, QUIT, BLOCKED, etc. */
	int			   processRunTime;       /* Total time process has run */
	int			   runTimeStart;		 /* used in cpu_time(), get_start_time() */
	void* args;							 /* argument passed to entryPoint */
	int            exitCode;			 /* this process's exit code */
	int            waiting;              /* 1 if blocked in k_wait */
	int			   signaled;			 /* 1 if process has been signaled to unblock */
	int			   joinTarget;		     /* pid this process is joining to */
} Process;

