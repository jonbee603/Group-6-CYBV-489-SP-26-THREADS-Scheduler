/*********************************************************************************
		Processes.h Final Implementation for the THREADS-Scheduler Project

					CYBV 489 - SP 26: Professor Li Xu
		   Group 6: Lexi Lamaide, Colin Martin, Jonathan Bergeron
**********************************************************************************/
#pragma once
typedef struct _process
{
	struct _process* nextReadyProcess;		/* Next process in the ready queue */
	struct _process* nextSiblingProcess;	/* Next sibling in the parent’s child list */
	struct _process* nextZombieProcess;		/* Next zombie child in the zombie list */

	struct _process* pParent;				/* Parent process (NULL for init/watchdog) */
	struct _process* pChildren;				/* First child in the child list */
	struct _process* zombieChildren;		/* Linked list of zombies for this process's children */
	struct _process* zombieTail;			/* Tail of the zombie list */

	char           name[MAXNAME];			/* Process name */
	char           startArgs[MAXARG];		/* Process arguments */
	void* context;							/* Process's current context */
	short          pid;						/* Process id (pid) */
	int            priority;				/* Process can have priority 0-5, 5 being highest priority */
	int (*entryPoint) (void*);				/* The entry point that is called from launch */
	char* stack;							/* For allocating stack memory */
	unsigned int   stacksize;				/* Length/size of the stack */
	int            status;					/* READY, QUIT, BLOCKED, etc. */
	int			   processRunTime;			/* Total time process has run */
	int			   runTimeStart;			/* used in cpu_time(), get_start_time() */
	void*          args;					/* argument passed to entryPoint */
	int            exitCode;				/* this process's exit code */
	int            waiting;					/* 1 if blocked in k_wait */
	int			   waitingSignaled;			/* 1 if signaled while waiting on k_wait */
	int			   signaled;				/* 1 if process has been signaled to unblock */
	int			   joinTarget;				/* pid this process is joining to */
} Process;

