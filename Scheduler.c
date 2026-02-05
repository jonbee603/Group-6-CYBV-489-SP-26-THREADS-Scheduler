/*********************************************************************************
        Scheduler.c Final Implementation for the THREADS-Scheduler Project

                    CYBV 489 - SP 26: Professor Li Xu
           Group 6: Lexi Lamaide, Colin Martin, Jonathan Bergeron
**********************************************************************************/

/*
Special Notes to pay attention to:

Don't forget to re-enable interrupts
Incorrect READY/RUNNING transitioning
Lost tracking on blocked processes
Improper parent-child cleanup

WEIRD HARD TO DEBUG BEHAVIORS:
Experiencing deadlock? - block/unblocking issue
TIME SLICE bugs - priority issue? fairness issues
*/
#define _CRT_SECURE_NO_WARNINGS

#define NUM_PRIORITIES 6
#define EMPTY    0
#define READY    1
#define RUNNING  2
#define BLOCKED  3
#define QUIT     4
#define JOINED   5

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

static Process* readyHead = NULL;
static Process* readyTail = NULL;
Process* ready_queues[NUM_PRIORITIES];

Process processTable[MAX_PROCESSES];
Process* runningProcess = NULL;

interrupt_handler_t* intVector; //TO IMPLEMENT

int nextPid = 1;
int debugFlag = 1;
int runTimeStart = 0; //used in read_time()

/* Group 6 Prototypes */
int bootstrap(void*);
int k_spawn(char*, int (*entryPoint)(void*), void*, int, int);
static int launch(void*);
int k_wait(int*);
void k_exit(int);
int k_kill(int, int); //TO IMPLEMENT
int k_getpid(void);
int k_join(int, int*); //TO IMPLEMENT
int unblock(int); //TO IMPLEMENT
int block(int); //TO IMPLEMENT
int signaled(void); //TO IMPLEMENT
int read_time();
int get_start_time();
DWORD read_clock(void);
void time_slice(); //TO IMPLEMENT
const char* status_name(int);
void display_process_table(void);   //TO IMPLEMENT
void dispatcher();
static void watchdog();
static void check_deadlock();
static inline void disableInterrupts();
static inline void enableInterrupts();
static void DebugConsole(char*, ...);
static int clamp_priority(int);
static void clock_handler(char*, uint8_t, uint32_t); //TO IMPLEMENT
//static interrupt_handler_t timer_handler(); //@colin, delete or keep?
void ready_queue_init(void);
void ready_enqueue(Process*);
Process* ready_dequeue(void);
void display_ready_queues(void);

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
   Name - launch()

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
   Name - k_wait()

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
   Name - k_exit()

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
   Name - k_kill()

   Purpose - Sends SIG_TERM to a process
             Marks process as signaled (does not terminate immediately)
             Invalid pid or signal halts kernel

   Parameters - pid, process ID of the target process
                signal, the signal number to send

   Returns - 0 on success

   TO IMPLEMENT
*************************************************************************/
int k_kill(int pid, int signal)
{
    int result = 0;
    return result;
}

/**************************************************************************
   Name - k_getpid()

   Purpose - Retrieves the process ID of the running process.

   Parameters - None

   Returns - The PID of the currently running process, or -1 if none.
*************************************************************************/
int k_getpid()
{
    return (runningProcess != NULL) ? runningProcess->pid : -1;
}

/**************************************************************************
   Name - k_join()

   Purpose - Waits for a specific process to terminate
             Illegal joins halt the kernel 

   Parameters - pid, process ID of the target process
                *pChildExitCode - the pointer to the process child's exit code
   
   TO IMPLEMENT & NOTES: (from lecture) Processes cannot join with themselves
   and cannot join with their parent's process. If the process is attempting
   to join itself or attempting to join a non-existing process, the kernel
   should be halted with stop(1); 
   
   OR if the process attempts to join its parent, the kernel should be halted
   with an error code of 2.

   I also noticed in lecture her function prototype arguments were pid, &exit_code
   which may differ from *pChildExitCode?
***************************************************************************/
int k_join(int pid, int* pChildExitCode)
{
    //stop(1); //halts the kernel with error 0x1

    //stop(2); //halts the kernel with error 0x2
    return 0;
}

/**************************************************************************
   Name - unblock()

   Purpose - Unblocks the calling process

   Parameters - pid, the process ID

   Retruns - ????
   
   TO IMPLEMENT & NOTES: The inverse of block(), moves a blocked process
   back to a READY state.
   Fails if pid is invalid or not blocked
   Does not immediately dispatch the process
*************************************************************************/
int unblock(int pid)
{
    //if (pid == valid process)
    return 0;
}

/*************************************************************************
   Name - block()

   Purpose - Blocks the calling process

   Parameters - newStatus for the block status

   Returns - -5 if signaled while blocked
   
   TO IMPLEMENT & NOTES: 0 on success, -5 if signaled while blocked??
   newStatus must be >10, in lecture she uses block_status instead of newStatus
   *Consider swapping newStatus with block_status if it makes more sense

   Are we just making the process NOT_READY?
*************************************************************************/
int block(int newStatus)
{
    return 0;
}

/*************************************************************************
   Name - signaled()

   Purpose - Checks whether the current process has been signaled

   Parameters - None

   Returns - 1 if signaled, 0 if otherwise

   Side Effects/Use Cases - Used by k_wait(), k_join(), and block()

   TO IMPLEMENT
*************************************************************************/
int signaled()
{
    return 0;
}

/*************************************************************************
   Name - readtime()

   Purpose - Retrieves the current run time of the process that is currently
   executing during the call. Measured in milliseconds (ms).

   Parameters - None

   Returns - The runtime of the current running process in milliseconds,
   or -1 if no process is running.
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

/*************************************************************************
   Name - get_start_time()

   Purpose - Records the start time for the current running process.
   This value is used as a baseline for measuring runtime.

   Parameters - None

   Returns - The start time in milliseconds.

   NOTES: In lecture, she said microseconds? Probably better to use our implementation of milli
*************************************************************************/
int get_start_time()
{
    /* Reads clock and divides by 1000 for time in ms */
    runTimeStart = (read_clock() / 1000); 

    //console_output(debugFlag, "Starting run time for %s is %d \n", runningProcess->name, runTimeStart);   //testline

    /* Return start time in ms */
    return runTimeStart;    
}

/*************************************************************************
   Name - read_clock()

   Purpose - Retrieves the current system clock tick count.

   Parameters - None

   Returns - The current system clock value in ticks.
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

/*************************************************************************
   Name - time_slice()

   Purpose - The time_slice function determines if the currently active
   process has exceeded its current time slice. If the quantum value has
   been exceeded the dispatcher is called.

   Parameters - None

   Returns - None

   TO IMPLEMENT & NOTES: Called by the timer interrupt handler
   Checks quantum expiration (80ms), which is milliseconds
   Calls dispatcher if time slice expired
   Not sure if we should replace read_clock with this function.
*************************************************************************/
void time_slice()
{
    //int timeQuantum .080; (in seconds, or we can just use 80)
    //if timer > quantum { dispatcher(); } //at some point in this function call dispatcher();
}

/**************************************************************************
   Name - display_process_table()

   Purpose - Iterates through the processTable and prints the following:
                pid, the process ID
                parent, NEED TO IMPLEMENT
                priority, the process priority level
                status, the process status
                and processRunTime, the CPU time

                Primarily used for debugging.

   Parameters - None

   Returns - None

   TO IMPLEMENT & NOTES:
   need to figure out how to display parent/child relationships. - Colin
   May need to adjust console output to align with expected solution.output.txt, which may involve removing name and adding parent? - Jon
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
}

/************************************************************************
   Name - dispatcher()

   Purpose - This is where context changes to the next process to run.
             
   Parameters - None

   Returns - Nothing

   TO IMPLEMENT & NOTES: 
             1. Decides which process goes to run next and then executes that process.
             2. Checks if the current process can continue running:
                (a) Has it been blocked or quitting?
                (b) Is it still the highest priority amnong READY processes?
                (c) Has it been time-sliced?
            3. Selects a new process and perform a context switch in order to get ir running.
            4. Follow Scheduling policy

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
   Name - watchdog()

   Purpose - The watchdoog keeps the system going when all other processes 
   are blocked.  It can be used to detect when the system is shutting down 
   as well as when a deadlock condition arises.

   Parameters - None

   Returns - Nothing
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

   Returns - Nothing
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
        else /* processes are running */
        {
            stop(1);
        }
    } 
}

/**************************************************************************
   Name - disableInterrupts()

   Purpose - Disables system interrupts by clearing the interrupt enable bit
   in the process status register (PSR). This function is used while 
   performing critical sections that must not be interrupted.

   Parameters - None

   Returns - Nothing
 *************************************************************************/
static inline void disableInterrupts()
{
    /* We ARE in kernel mode */
    int psr = get_psr();

    psr = psr & ~PSR_INTERRUPTS;

    set_psr(psr);
}

/**************************************************************************
   Name - enableInterrupts()

   Purpose - Enables system interrupts by setting the interrupt enable bit
   in the process status register (PSR). This function should only be called
   while the processor is in kernel mode, as it directly manipulates the PSR.

   Parameters - None

   Returns - Nothing
 *************************************************************************/
static inline void enableInterrupts()
{
    /* We ARE in kernel mode */
    int psr = get_psr();

    psr = psr | PSR_INTERRUPTS;

    set_psr(psr);

}

/**************************************************************************
   Name - DebugConsole()

   Purpose - Prints the message to the console_output if in debug mode

   Parameters - format string and va args

   Returns - Nothing
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

/**************************************************************************
   Name - clamp_priority()

   Purpose - Ensures that the priority value supplied by the caller is 
   within the valid range of NUM_PRIORITIES.

   Parameters - p, the priority value to the clamped

   Returns - The clamped priority value, p (0 ... NUM_PRIORITIES-1)
*************************************************************************/
static int clamp_priority(int p)
{
    if (p < 0)
        return 0;

    if (p >= NUM_PRIORITIES)
        return NUM_PRIORITIES - 1;

    return p;
}

/**************************************************************************
   Name - clock_handler()

   Purpose - Handles the timer interrupt.

   Parameters - char *deviceName, uint8_t command, uint32_t status

   Returns - 0

   TO IMPLEMENT & NOTES: Renamed and prototype aligned with lecture
   Used to be timer_handler()
*************************************************************************/
static void clock_handler(char* deviceName, uint8_t command, uint32_t status)
{
    time_slice();
}

/**************************************************************************
   Name - timer_handler()

   Purpose - Handles the timer interrupt. TO IMPLEMENT.

   Parameters - None

   Returns - 0
   NOTES: @Colin, do we need this?
***************************************************************************/
//static interrupt_handler_t timer_handler()
//{
//    read_clock();
//    return 0;
//    /*
//       if (read_time >= 80)
//       {
//       dispatcher();
//       }
//    */
//}

/**************************************************************************
   Name - ready_queue_init()

   Purpose - Initializes all ready queues to empty. This function must be
   called before any process is enqueued.

   Parameters - None

   Returns - Nothing
*************************************************************************/
void ready_queue_init(void)
{
    for(int i = 0; i < NUM_PRIORITIES; i++)
    {
        ready_queues[i] = NULL;
	}
}

/**************************************************************************
   Name - ready_enqueue()

   Purpose - Adds a process to the end of the ready queue that corresponds
   to the process's priroity.

   Parameters - p, the pointer of the process to be enqueued

   Returns - Nothing
*************************************************************************/
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

/**************************************************************************
   Name - ready_dequeue()

   Purpose - Removes and returns the process at the head of the highest
   priority non-empty ready queue. If all queues are empty, returns NULL.

   Parameters - None

   Returns - Pointer to the dequeued process, or NULL if no ready process.
*************************************************************************/
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

/**************************************************************************
   Name - display_ready_queues()

   Purpose - Prints the contents of all ready queues to the console for
   debugging purposes.

   Parameters - None

   Returns - Nothing
*************************************************************************/
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

/**************************************************************************
   Name - check_io_scheduler()

   Purpose - Checks IO. Since it is not implemented it returns false.

   Parameters - None

   Returns - False

   TO IMPLEMENT
*************************************************************************/
int check_io_scheduler()
{
    return false;
}