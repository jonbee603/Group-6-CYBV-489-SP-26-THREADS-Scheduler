/**************************************************************************
        Scheduler.c Implementation for Phase 1 of the THREADS Project

                    CYBV 489 - SP 26 - Professor Li Xu
           Group 6:Lexi Lamaide, Colin Martin, Jonathan Bergeron
*************************************************************************/
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
int runTimeStart = 0;

static void watchdog();
static inline void disableInterrupts();
static inline void enableInterrupts();
void dispatcher();
static int launch(void*);
static void check_deadlock();
static void DebugConsole(char* format, ...);

//Group 6 Prototypes
static int clamp_priority(int p);
Process* ready_queues[NUM_PRIORITIES];
void ready_queue_init(void);
void ready_enqueue(Process* p);
Process* ready_dequeue(void);
void display_ready_queues(void);
static interrupt_handler_t timer_handler();
const char* status_name(int);
int read_time();
int get_start_time();

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
    ready_queue_init();
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
	//display_process_table();  //test line

    /* This should never return since we are not a real process. */
    dispatcher();

    stop(-3);
    return 0;
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
*************************************************************************/
int k_spawn(char* name, int (*entryPoint)(void*), void* arg, int stacksize, int priority)
{
    int proc_slot = -1;
    Process* pNewProc = NULL;

    //DebugConsole("k_spawn(): creating process %s\n", name);   //test line

    disableInterrupts();
	//console_output(debugFlag, "Interrupts disabled!\n");      //test line

    /* Validate all of the parameters, starting with the name. */
    if (name == NULL)
    {
        console_output(debugFlag, "k_spawn(): Name value is NULL.\n");
        return -1;
    }
    if (strlen(name) >= (MAXNAME - 1))
    {
        console_output(debugFlag, "k_spawn(): Process name is too long.  Halting...\n");
        stop(1);
    }
    if (entryPoint == NULL)
    {
        console_output(debugFlag, "k_spawn(): entryPoint is NULL.\n");
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
        console_output(debugFlag, "k_spawn(): invalid priority %d. Calling priority clamp\n", priority);
		clamp_priority(priority);           
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
        console_output(debugFlag, "k_spawn(): No empty slot in process table.\n");
        return -1;
    }

    pNewProc = &processTable[proc_slot];

    /* Setup the entry in the process table. (PCB initialization) */
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
        console_output(debugFlag, "k_spawn(): context_initialize failed.\n");
        pNewProc->pid = -1;
        pNewProc->status = EMPTY;
        return -1;
    }

    /* Add the process to the ready list. */
    ready_enqueue(pNewProc);

    //check_deadlock();                                                                                                             //testline - Added this to test and see if deadlock would return with processes still active
    //console_output(debugFlag, "k_spawn(): pid=%d, name=%s, priority=%d\n", pNewProc->pid, pNewProc->name, pNewProc->priority);    //test line
    //display_ready_queues();                                                                                                       //test line

    return pNewProc->pid;
}

/**************************************************************************
   Name - launch

   Purpose - Utility function that makes sure the environment is ready,
             such as enabling interrupts, for the new process.

   Parameters - none

   Returns - nothing
*************************************************************************/
static int launch(void* args)
{
    //DebugConsole("launch(): started: %s\n", runningProcess->name);    //test line

    /* Enable interrupts */
	enableInterrupts();

	//console_output(debugFlag, "Interrupts enabled!\n");               //test line

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

    /* Update process run time upon quitting */
    runningProcess->processRunTime = read_time();   

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
    /* If running process is null return -1 for time */
    if (runningProcess == NULL) 
    {
        return -1;
    }
    if (runningProcess != NULL)
    {
        /* Current time program has been running in ms */
        int currentrunTime = (read_clock() / 1000) - runTimeStart; 

        /* Set process run time to current run time in ms */
        runningProcess->processRunTime = currentrunTime;    

        //console_output(debugFlag, "Current run time for %s is %d\n", runningProcess->name, currentrunTime);   //testline

        /* Return run time of currently running process in ms */
        return runningProcess->processRunTime;   
    }
   
}

int get_start_time()
{
    /* Reads clock and divides by 1000 for time in ms */
    runTimeStart = (read_clock() / 1000); 

    //console_output(debugFlag, "Starting run time for %s is %d \n", runningProcess->name, runTimeStart);   //testline

    /* Return start time in ms */
    return runTimeStart;    
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

/**************************************************************************
   Name - display_process_table

   Purpose - Iterates through the processTable and prints the items in it

   Parameters - None

   Returns - nothing
*************************************************************************/
void display_process_table()
{
    /* Title for table print */
    console_output(debugFlag, "\nPROCESS TABLE\n"); 
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid != -1)
        {
            console_output(debugFlag, "pid=%d, priority=%d, status=%s, name=%s, run time=%d\n",
                processTable[i].pid,
                processTable[i].priority,
                status_name(processTable[i].status),
                processTable[i].name,
                processTable[i].processRunTime);
        }
    }
    /*
    * TO IMPLEMENT:
    *        need to figure out how to display parent/child relationships. - Colin
    */
}

/************************************************************************
   Name - dispatcher

   Purpose - This is where context changes to the next process to run.

   Parameters - none

   Returns - nothing
*************************************************************************/
void dispatcher()
{
	runningProcess = ready_dequeue();

    if (runningProcess != NULL)
    {
        runningProcess->status = RUNNING;

        /* Calls get start time at beginning of process run */
        get_start_time(); 
    }
        
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
static void watchdog()
{
    //DebugConsole("watchdog(): called\n"); //test line

    while (1)
    {
        /* as the system idles here, the timer is to keep the program alive if processes are running */
        check_deadlock();
    }
}

/**************************************************************************
   Name - check_deadlock()

   Purpose - Checks if deadlock has occurred by traversing the processTable pids

   Parameters - none

   Returns - nothing
 *************************************************************************/
static void check_deadlock()
{
    if (check_io() == 1)
    {
        return;
    }
    //display_process_table();  //testline

    /* Begin indexing after watchdog */
    for (int i = 1; i < MAX_PROCESSES; i++)
    {
        /* Check if watchdog is the only process running */
        if (processTable[0].status == RUNNING && processTable[i].status != RUNNING) //
        {
            console_output(debugFlag, "All processes completed.\n");
            runningProcess->processRunTime = read_time();

            //display_process_table();      //testline

            stop(0);
        }

        /* processes are running, return = not idle */
        else
        {
            return;
        }
    } 
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

static inline void enableInterrupts()
{

    /* We ARE in kernel mode */

    int psr = get_psr();

    psr = psr | PSR_INTERRUPTS;

    set_psr(psr);

} /* enableInterrupts function - Colin */

/**************************************************************************
   Name - DebugConsole

   Purpose - Prints  the message to the console_output if in debug mode

   Parameters - format string and va args

   Returns - nothing
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
    /* TO DO: Implement call to dispatcher if run time exceeds time slice of 80ms upon checking.
       if (read_time >= 80)
       {
       dispatcher();
       }
    */
}
void ready_queue_init(void)
{
    for(int i = 0; i < NUM_PRIORITIES; i++)
    {
        ready_queues[i] = NULL;
	}
}

void ready_enqueue(Process* p)
{
    int prio = p->priority;
    p->nextReadyProcess = NULL;

    if (ready_queues[prio] == NULL)
    {
        ready_queues[prio] = p;
    }
    else
    {
		Process* current = ready_queues[prio];
        while (current->nextReadyProcess != NULL)
        {
            current = current->nextReadyProcess;
        }
		current->nextReadyProcess = p;
    }
}

Process* ready_dequeue(void)
{
	for (int prio = NUM_PRIORITIES - 1; prio >= 0; prio--)  //Dequeues from highest priority queue first
    {
		if (ready_queues[prio] != NULL)                     //If queue is not empty
        {
			Process* p = ready_queues[prio];                //Get process at head of queue
			ready_queues[prio] = p->nextReadyProcess;       //Update head to next process in queue
			p->nextReadyProcess = NULL;                     //Clear next pointer of dequeued process
            return p;
        }
    }
	return NULL;
}

void display_ready_queues(void) {
	console_output(debugFlag, "\nREADY QUEUES:\n");
    for (int prio = 0; prio < NUM_PRIORITIES; prio++) 
    {
        console_output(debugFlag,"Priority %d: ", prio);
        Process* current = ready_queues[prio];

        if (current == NULL) 
        {
            console_output(debugFlag,"EMPTY\n");
            continue;
        }

        while (current != NULL) 
        {
            console_output(debugFlag,"[PID=%d %s] -> ", current->pid, current->name);
            current = current->nextReadyProcess;
        }

        console_output(debugFlag,"NULL\n");
    }
}
