
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

#define NUM_PRIORITIES 6
#define EMPTY    0
#define READY    1
#define RUNNING  2
#define BLOCKED  3
#define QUIT     4
#define JOINED   5


Process processTable[MAX_PROCESSES];
Process* runningProcess = NULL;
int nextPid = 1;
int debugFlag = 1;
static Process* readyHead = NULL;
static Process* readyTail = NULL;

static int watchdog(void* dummy);
static inline void disableInterrupts();
void dispatcher();
static int launch(void*);
static void check_deadlock();
static void DebugConsole(char* format, ...);

static void ready_init(void);
static void ready_enqueue(Process* p);
static Process* ready_dequeue(void);
static interrupt_handler_t timer_handler();
const char* status_name(int);

/* DO NOT REMOVE */
extern int SchedulerEntryPoint(void* pArgs);
int check_io_scheduler();
check_io_function check_io;


/*************************************************************************
   bootstrap()

   Purpose - This is the first function called by THREADS on startup.

             The function must setup the OS scheduler and primitive
             functionality and then spawn the first two processes.

             The first two process are the watchdog process
             and the startup process SchedulerEntryPoint.

             The statup process is used to initialize additional layers
             of the OS.  It is also used for testing the scheduler
             functions.

   Parameters - Arguments *pArgs - these arguments are unused at this time.

   Returns - The function does not return!

   Side Effects - The effects of this function is the launching of the kernel.

 *************************************************************************/
int bootstrap(void* pArgs)
{
    int result; /* value returned by call to spawn() */

    /* set this to the scheduler version of this function.*/
    check_io = check_io_scheduler;

    /* Initialize the process table. */
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        processTable[i].pid = -1;
        processTable[i].status = EMPTY;
        processTable[i].context = NULL;

        processTable[i].pParent = NULL;
        processTable[i].pChildren = NULL;
        processTable[i].nextReadyProcess = NULL;
        processTable[i].nextSiblingProcess = NULL;

        processTable[i].args = NULL;
        processTable[i].exitCode = 0;
        processTable[i].waiting = 0;
        processTable[i].zombiePid = -1;
        processTable[i].zombieExitCode = 0;
    }
    /* Initialize the Ready list, etc. */
    ready_init();
    runningProcess = NULL;
    nextPid = 1;

    /* Initialize the clock interrupt handler */
    interrupt_handler_t* handlers;              //Handlers protoype
    handlers = get_interrupt_handlers();        //Call get_interrupt_handlers function
    handlers[THREADS_TIMER_INTERRUPT] = timer_handler(); //Set handlers timer interrupt index to call timer handler function     

    /* startup a watchdog process */
    result = k_spawn("watchdog", watchdog, NULL, THREADS_MIN_STACK_SIZE, LOWEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "Scheduler(): spawn for watchdog returned an error (%d), stopping...\n", result);
        stop(1);
    }

    /* start the test process, which is the main for each test program.  */
    result = k_spawn("Scheduler", SchedulerEntryPoint, NULL, 2 * THREADS_MIN_STACK_SIZE, HIGHEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "Scheduler(): spawn for SchedulerEntryPoint returned an error (%d), stopping...\n", result);
        stop(1);
    }

    /* Initialized and ready to go!! */
	display_process_table();
    /* This should never return since we are not a real process. */
    dispatcher();
    //We use the dispatcher here to context switch and never return

    while (1)
    {
        dispatcher();
    }

}

/*************************************************************************
   k_spawn()

   Purpose - spawns a new process.

             Finds an empty entry in the process table and initializes
             information of the process.  Updates information in the
             parent process to reflect this child process creation.

   Parameters - the process's entry point function, the stack size, and
                the process's priority.

   Returns - The Process ID (pid) of the new child process
             The function must return if the process cannot be created.

************************************************************************ */
int k_spawn(char* name, int (*entryPoint)(void*), void* arg, int stacksize, int priority)
{
    int proc_slot = -1;
    Process* pNewProc = NULL;

    //comment out later?//
    DebugConsole("k_spawn(): creating process %s\n", name);
    ////////////////////

    disableInterrupts();

    /* Validate all of the parameters, starting with the name. */
    if (name == NULL)
    {
        console_output(debugFlag, "k_spawn(): Name value is NULL.\n");
        return -1;
    }
    if (strlen(name) >= (MAXNAME - 1))
    {
        console_output(debugFlag, "spawn(): Process name is too long.  Halting...\n");
        stop(1);
    }
    if (entryPoint == NULL)
    {
        console_output(debugFlag, "spawn(): entryPoint is NULL.\n");
        return -1;
    }
    if (entryPoint == NULL)
    {
        console_output(debugFlag, "k_spawn(): entryPoint is NULL.\n");
        return -1;
    }
    if (stacksize < THREADS_MIN_STACK_SIZE)
    {
        console_output(debugFlag, "k_spawn(): stacksize %d < THREADS_MIN_STACK_SIZE.\n", stacksize);
        return -2;
    }
    if (priority < 0 || priority > HIGHEST_PRIORITY)
    {
        console_output(debugFlag, "k_spawn(): invalid priority %d. Halting...\n", priority);
        stop(1);
    }

    /* Find an empty slot in the process table */
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid == -1)
        {
            proc_slot = i;
            break;
        }
    }
    if (proc_slot < 0)
    {
        console_output(debugFlag, "spawn(): No empty slot in process table.\n");
        return -1;
    }

    pNewProc = &processTable[proc_slot];

    /* Setup the entry in the process table. (PCB initialization)*/
    strcpy(pNewProc->name, name);
    pNewProc->pid = (short)nextPid++;
    pNewProc->priority = priority;
    pNewProc->entryPoint = entryPoint;
    pNewProc->args = arg;

    pNewProc->status = READY;
    pNewProc->pChildren = NULL;
    pNewProc->nextSiblingProcess = NULL;
    pNewProc->nextReadyProcess = NULL;

    pNewProc->waiting = 0;
    pNewProc->zombiePid = -1;
    pNewProc->zombieExitCode = 0;
    pNewProc->exitCode = 0;

    /* If there is a parent process, add this to the list of children. */
    if (runningProcess != NULL)
    {
        pNewProc->pParent = runningProcess;
        pNewProc->nextSiblingProcess = runningProcess->pChildren;
        runningProcess->pChildren = pNewProc;
    }
    else
    {
        pNewProc->pParent = NULL;
    }

    /* Initialize context for this process */
    pNewProc->context = context_initialize(launch, stacksize, arg);
    if (pNewProc->context == NULL)
    {
        console_output(debugFlag, "spawn(): context_initialize failed.\n");
        pNewProc->pid = -1;
        pNewProc->status = EMPTY;
        return -1;
    }

    /* Add the process to the ready list. */
    ready_enqueue(pNewProc);

    return pNewProc->pid;

    console_output(debugFlag, "k_spawn(): pid=%d, name=%s, priority=%d\n", pNewProc->pid, pNewProc->name, pNewProc->priority);

    return pNewProc->pid;

} /* spawn */

/**************************************************************************
   Name - launch

   Purpose - Utility function that makes sure the environment is ready,
             such as enabling interrupts, for the new process.

   Parameters - none

   Returns - nothing
*************************************************************************/
static int launch(void* args)
{
    DebugConsole("launch(): started: %s\n", runningProcess->name);

    /* Enable interrupts */

    /* Call the function passed to spawn and capture its return value */
    int rc = runningProcess->entryPoint(runningProcess->args);

    DebugConsole("Process %d returned to launch\n", runningProcess->pid);

    /* Stop the process gracefully */
    k_exit(rc);

    return 0;
}


/**************************************************************************
   Name - k_wait

   Purpose - Wait for a child process to quit.  Return right away if
             a child has already quit.

   Parameters - Output parameter for the child's exit code.

   Returns - the pid of the quitting child, or
        -4 if the process has no children
        -5 if the process was signaled in the join

************************************************************************ */
int k_wait(int* code)
{
    /* No children */
    if (runningProcess->pChildren == NULL)
    {
        return -4;
    }

    /* If a child has already quit, return immediately */
    if (runningProcess->zombiePid != -1)
    {
        if (code) *code = runningProcess->zombieExitCode;

        int kidpid = runningProcess->zombiePid;
        runningProcess->zombiePid = -1;

        /* We spawn one child, so we can clear the list here */
        runningProcess->pChildren = NULL;

        return kidpid;
    }

    /* Otherwise, block this process and run something else. */
    runningProcess->waiting = 1;
    runningProcess->status = BLOCKED;

    dispatcher();

    /* When we resume, child exit info should be available */
    if (runningProcess->zombiePid != -1)
    {
        if (code) *code = runningProcess->zombieExitCode;

        int kidpid = runningProcess->zombiePid;
        runningProcess->zombiePid = -1;
        runningProcess->pChildren = NULL;

        return kidpid;
    }

    return -5;
}

/**************************************************************************
   Name - k_exit

   Purpose - Exits a process and coordinates with the parent for cleanup
             and return of the exit code.

   Parameters - the code to return to the grieving parent

   Returns - nothing

*************************************************************************/
void k_exit(int code)

{
    runningProcess->exitCode = code;
    runningProcess->status = QUIT;

    /* If we have a parent, notify it so k_wait() can return the status. */
    if (runningProcess->pParent != NULL)
    {
        Process* parent = runningProcess->pParent;

        parent->zombiePid = runningProcess->pid;
        parent->zombieExitCode = code;

        if (parent->waiting)
        {
            parent->waiting = 0;
            parent->status = READY;
            ready_enqueue(parent);
        }
    }

    /* Switch to next ready process */
    dispatcher();

    /* Should not return here */
    stop(0);

}

/**************************************************************************
   Name - k_kill

   Purpose - Signals a process with the specified signal

   Parameters - Signal to send

   Returns -
*************************************************************************/
int k_kill(int pid, int signal)
{
    int result = 0;
    return result;
}

/**************************************************************************
   Name - k_getpid
*************************************************************************/
int k_getpid()
{
    return (runningProcess != NULL) ? runningProcess->pid : -1;
}

/**************************************************************************
   Name - k_join
***************************************************************************/
int k_join(int pid, int* pChildExitCode)
{
    return 0;
}

/**************************************************************************
   Name - unblock
*************************************************************************/
int unblock(int pid)
{
    return 0;
}

/*************************************************************************
   Name - block
*************************************************************************/
int block(int newStatus)
{
    return 0;
}

/*************************************************************************
   Name - signaled
*************************************************************************/
int signaled()
{
    return 0;
}
/*************************************************************************
   Name - readtime
*************************************************************************/
int read_time()
{
    return runningProcess->processRunTime;  //Read run time of currently running process - Colin
}

/*************************************************************************
   Name - readClock
*************************************************************************/
DWORD read_clock()
{
    return system_clock();
}

const char* status_name(int st) {
    switch (st) {
	case EMPTY:   return "EMPTY";
    case READY:   return "READY";
	case RUNNING: return "RUNNING";
    case BLOCKED: return "BLOCKED";
	case QUIT:    return "QUIT";
	case JOINED:   return "JOINED";
    default:      return "UNKNOWN";
    }
}

void display_process_table()
{
    console_output(debugFlag, "\nPROCESS TABLE\n"); //Title for table print
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid != 0)
        {
            console_output(debugFlag, "pid=%d, priority=%d, status=%s, name=%s\n",
                processTable[i].pid,
                processTable[i].priority,
                status_name(processTable[i].status),
                processTable[i].name);
        }
    }
    /*
    need to figure out how to display parent/child relationships and CPU time used. - Colin
    */

}

/**************************************************************************
   Name - dispatcher

   Purpose - This is where context changes to the next process to run.

   Parameters - none

   Returns - nothing

*************************************************************************/
void dispatcher()
{
    Process* nextProcess = ready_dequeue();

    if (nextProcess == NULL)
    {
        return;
    }

    runningProcess = nextProcess;
    runningProcess->status = RUNNING;

    /* IMPORTANT: context switch enables interrupts. */
    context_switch(runningProcess->context);
}


/**************************************************************************
   Name - watchdog

   Purpose - The watchdoog keeps the system going when all other
         processes are blocked.  It can be used to detect when the system
         is shutting down as well as when a deadlock condition arises.

   Parameters - none

   Returns - nothing
   *************************************************************************/
static int watchdog(void* dummy)
{
    DebugConsole("watchdog(): called\n");
    while (1)
    {
        check_deadlock();
    }
    console_output(debugFlag, "All processes completed!\n");        //Output message before watchdog exit - Colin
    return 0;
}

/* check to determine if deadlock has occurred... */
static void check_deadlock()
{
}

/*
 * Disables the interrupts.
 */
static inline void disableInterrupts()
{

    /* We ARE in kernel mode */


    int psr = get_psr();

    psr = psr & ~PSR_INTERRUPTS;

    set_psr(psr);

} /* disableInterrupts */

/**************************************************************************
   Name - DebugConsole
   Purpose - Prints  the message to the console_output if in debug mode
   Parameters - format string and va args
   Returns - nothing
   Side Effects -
*************************************************************************/
static void DebugConsole(char* format, ...)
{
    char buffer[2048];
    va_list argptr;

    if (debugFlag)
    {
        va_start(argptr, format);
        vsprintf(buffer, format, argptr);
        console_output(TRUE, buffer);
        va_end(argptr);

    }
}

/* there is no I/O yet, so return false. */
int check_io_scheduler()
{
    return false;
}

/* If priority is out of bounds, this function will change it to 0 or 5*/
static int clamp_priority(int p)
{
    if (p < 0)
        return 0;

    if (p >= NUM_PRIORITIES)
        return NUM_PRIORITIES - 1;

    return p;
}

static interrupt_handler_t timer_handler()
{
    read_clock();
    return 0;
    /* Need to implement check to see if current running process run time excess time slice given
    of 80ms. If time exceeds 80ms, call dispatch() to evaluate if there is an equal prio
    process ready to run. If time has not exceeded 80ms, continue process.
    Higher prio process should have it's own interrupt. -Colin */
}
static void ready_init(void)
{
    readyHead = readyTail = NULL;
}

static void ready_enqueue(Process* p)
{
    p->nextReadyProcess = NULL;
    if (readyTail != NULL)
    {
        readyTail->nextReadyProcess = p;
        readyTail = p;
    }
    else
    {
        readyHead = readyTail = p;
    }
}

static Process* ready_dequeue(void)
{
    Process* p = readyHead;
    if (p == NULL)
        return NULL;

    readyHead = p->nextReadyProcess;
    if (readyHead == NULL)
        readyTail = NULL;

    p->nextReadyProcess = NULL;
    return p;
}
