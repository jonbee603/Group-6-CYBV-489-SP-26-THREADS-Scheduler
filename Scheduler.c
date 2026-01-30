
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

#define NUM_PRIORITIES (HIGHEST_PRIORITY + 1)
#define STATUS_READY 1
#define STATUS_BLOCKED 2
#define STATUS_QUIT 3
#define STATUS_WAITING 4
#define STATUS_JOINED 5

Process processTable[MAX_PROCESSES]; 
//The processTable array
static Process* readyList[NUM_PRIORITIES][MAX_PROCESSES];
//readyList is an array which is indexed by priority 0 - 5, with 5 being the highest

//Changing ready list to an array of arrays to handle multiple processes at same priority -Colin

Process* runningProcess = NULL;
//current executing PCB
int nextPid = 1; 
//next free pid (0 is unused)
int debugFlag = 1;
//to enable console output

/*blocked singly-linked list of PCBs whos status != READY*/
// static Process* blockedList = NULL;
// TO IMPLEMENT ///////////////////////////

static int watchdog(char*);
static inline void disableInterrupts();
void dispatcher();
static int launch(void*);
static void check_deadlock();
static void DebugConsole(char* format, ...);

//student implemented functions//
static void   readyq_push(Process* proc);
static Process* readyq_pop_prio(int prio);
static Process* readyq_pop_highest(void);
static Process* readyq_remove_pid(short pid);
static interrupt_handler_t timer_handler();                    //Timer Handler function - Colin

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
        processTable[i] = (Process){0};
        //clears out the table

    /* Initialize the Ready list, etc. */
    for (int j = 0; j < NUM_PRIORITIES; j++)
        for(int i = 0; i < MAX_PROCESSES; i++)
            readyList[j][i] = NULL;
        //clears the ready queue

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
        console_output(debugFlag,"Scheduler(): spawn for SchedulerEntryPoint returned an error (%d), stopping...\n", result);
        stop(1);
    }

    /* Initialized and ready to go!! */
    /* This should never return since we are not a real process. */
    dispatcher();
    //We use the dispatcher here to context switch and never return

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

************************************************************************ */
int k_spawn(char* name, int (*entryPoint)(void *), void* arg, int stacksize, int priority)
{
    int proc_slot;
    struct _process* pNewProc;

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
        console_output(debugFlag, "k_spawn(): Process name is too long. Halting...\n");
        stop(1);
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
    proc_slot = 1;  // just use 1 for now!

    //traverse table via loop
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid == 0)
        {
            proc_slot = i; //if empty slot, select it
            break;
        }
    }
    if (proc_slot == -1)
    {
        console_output(debugFlag, "k_spawn(): process table full.\n");
        return -4;
    }

    //assign process to new slot in table
    pNewProc = &processTable[proc_slot];

    /* Setup the entry in the process table. (PCB initialization)*/
    strcpy(pNewProc->name, name);
    pNewProc->name[MAXNAME - 1] = '\0'; //ensures both the name is within length limits and null terminated
    pNewProc->pid = nextPid++;
    pNewProc->priority = priority;
    pNewProc->entryPoint = entryPoint;
    pNewProc->stacksize = stacksize;
    pNewProc->stack = NULL;
    pNewProc->pParent = runningProcess;
    pNewProc->status = STATUS_READY;

    /* If there is a parent process,add this to the list of children. */
    if (runningProcess != NULL)
    {
        pNewProc->nextSiblingProcess = runningProcess->pChildren;
        runningProcess->pChildren = pNewProc;
    }

    /* Add the process to the ready list. */

    /* Initialize context for this process, but use launch function pointer for
     * the initial value of the process's program counter (PC)
    */
    pNewProc->context = context_initialize(launch, stacksize, arg);

    //Sends to the ready queue
    readyq_push(pNewProc);

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
static int launch(void *args)
{

    DebugConsole("launch(): started: %s\n", runningProcess->name);

    /* Enable interrupts */

    /* Call the function passed to spawn and capture its return value */
    DebugConsole("Process %d returned to launch\n", runningProcess->pid);

    /* Stop the process gracefully */

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
    int result = 0;
    return result;

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
    return 0;
}

/**************************************************************************
   Name - k_getpid
*************************************************************************/
int k_getpid()
{
    return 0;
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

//Switch case from demo file to convert status int to string - Colin
const char* status_name(int status) {       
    switch (status) {
    case STATUS_READY:      return "READY";
    case STATUS_BLOCKED:    return "BLOCKED";
    case STATUS_QUIT:       return "QUIT";
    case STATUS_WAITING:    return "WAITING";
    case STATUS_JOINED:     return "JOINED";
    default:                return "UNKNOWN";
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
	display_process_table();  //Displaying current results of process table before context switch -Colin

    Process *nextProcess = NULL;

    /* IMPORTANT: context switch enables interrupts. */
    
    /*
    context_switch(runningProcess->nextReadyProcess);
    Tried context switch from running process to next ready process being pointed
    to by running process, but running process is NULL
    */
    
    context_switch(nextProcess->context);
} 

/**************************************************************************
   Name - watchdog

   Purpose - The watchdoog keeps the system going when all other
         processes are blocked.  It can be used to detect when the system
         is shutting down as well as when a deadlock condition arises.

   Parameters - none

   Returns - nothing
   *************************************************************************/
static int watchdog(char* dummy)
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

    set_psr( psr);

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

//copied directly from scheduler_demo.c, may need to integrate to our project
static void readyq_push(Process* proc)
{
    int prio = clamp_priority(proc->priority);
    proc->nextReadyProcess = NULL;

    if (readyList[prio][0] == NULL) {
        readyList[prio][0] = proc;
        return;
    }
    Process* cur = readyList[prio][0];
    while (cur->nextReadyProcess) cur = cur->nextReadyProcess;
    cur->nextReadyProcess = proc;
}

static Process* readyq_pop_prio(int prio)
{
    prio = clamp_priority(prio);
    Process* head = readyList[prio][0];
    if (!head) return NULL;
    readyList[prio][0] = head->nextReadyProcess;
    head->nextReadyProcess = NULL;
    return head;
}

static Process* readyq_pop_highest(void)
{
    for (int p = NUM_PRIORITIES - 1; p >= 0; --p) {
        Process* proc = readyq_pop_prio(p);
        if (proc) return proc;
    }
    return NULL;
}

static Process* readyq_remove_pid(short pid)
{
    Process* target = &processTable[pid % MAX_PROCESSES];
    int prio = clamp_priority(target->priority);
    Process* prev = NULL, * cur = readyList[prio][0];

    while (cur) {
        if (cur == target) {
            if (prev) prev->nextReadyProcess = cur->nextReadyProcess;
            else      readyList[prio][0] = cur->nextReadyProcess;
            cur->nextReadyProcess = NULL;
            return cur;
        }
        prev = cur;
        cur = cur->nextReadyProcess;
    }
    return NULL;
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