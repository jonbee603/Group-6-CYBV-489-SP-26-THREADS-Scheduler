/*********************************************************************************
        Scheduler.c Final Implementation for the THREADS-Scheduler Project

                    CYBV 489 - SP 26: Professor Li Xu
           Group 6: Lexi Lamaide, Colin Martin, Jonathan Bergeron
**********************************************************************************/

#define _CRT_SECURE_NO_WARNINGS

#define NUM_PRIORITIES 6
#define EMPTY    0
#define READY    1
#define RUNNING  2
#define BLOCKED  3
#define QUIT     4
#define JOINED   5
#define K_WAIT  11
#define K_JOIN  12

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

Process* ready_queues[NUM_PRIORITIES];
static char argBuffer[MAX_PROCESSES][THREADS_MAX_NAME];
Process processTable[MAX_PROCESSES];
Process* runningProcess = NULL;
int nextPid = 1;
int debugFlag = 1;

/* Group 6 Prototypes */
int bootstrap(void*);
int k_spawn(char*, int (*entryPoint)(void*), void*, int, int);
int k_wait(int*);
int k_join(int, int*);
int k_kill(int, int);
void k_exit(int);
int k_getpid(void);
void time_slice();
void dispatcher();
int signaled(void);
int block(int);
int unblock(int);
int get_start_time();
int read_time();
uint32_t read_clock(void);
void display_process_table(void);
const char* status_name(int);
static void watchdog();
static void check_deadlock();
static inline void disableInterrupts();
static inline void enableInterrupts();
static void DebugConsole(char*, ...);
static void clock_handler(char*, uint8_t, uint32_t);
void ready_queue_init(void);
void ready_enqueue(Process*);
Process* ready_dequeue(void);
void display_ready_queues(void);
static int launch(void*);
void cleanup_process(Process* proc);

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
        processTable[i].waitingSignaled = 0;
        processTable[i].joinTarget = -1;
    }

    /* Initialize the Ready list, etc. */
    ready_queue_init();
    runningProcess = NULL;
    nextPid = 1;

    /* Initialize the clock interrupt handler */
    interrupt_handler_t* handlers;
    handlers = get_interrupt_handlers();
    handlers[THREADS_TIMER_INTERRUPT] = clock_handler;

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

    /* This should never return since we are not a real process. */
    dispatcher();

    stop(-3);
    return 0;
}

/*************************************************************************
   k_spawn()

   Purpose - The k_spawn function creates a new process in the kernel at the specified priority.
             The process begins at the function pointed to by entry_point, which is called with a
             single parameter with the value in arg. The THREADS library manages the stack
             for each context, but the caller needs to provide the stack size in stack_size when
             creating the context.

   Parameters - name, name of the new process
                entry_point, a function pointer that serves as the entry point of the new process
                arg, This must point to a string that is passed to the new process
                     as a parameter to the entry_point function
                stack_size, The size of the stack used for the process.
                priority, The new processes' priority (0-5)

   Returns - Upon success, the function returns the process id (pid) of the
             newly created process. The function should an error code in an
             error occurs:
             Return Values
                <pid> Process ID of the new process.
                -1 A parameter is missing or invalid.
                -2 The specified stack size is out of
                range.
                -3 The specified priority is out of range.
                -4 The process cannot be created
                because the process table is full.

   Notes - The strings pointed to by the name and arg parameters cannot be larger than THREADS_MAX_NAME
           in size. If either of these strings are larger than THREADS_MAX_NAME, the kernel must be halted with
           a call to stop and an error code of 1:
           This is the function where the context of the new process is initialized with context_initialize.
           Save the new context in the process table to use when it’s time to start the process or return
           processing to the process via the context_switch function.
           Important: Interrupts must be enabled when a process is started.
*************************************************************************/
int k_spawn(char* name, int (*entry_point)(void*), void* arg, int stack_size, int priority)
{
    /* Verifies we are in kernel mode */
    if ((get_psr() & PSR_KERNEL_MODE) == 0)
    {
        console_output(debugFlag, "Kernel mode expected, but function called in user mode.\n");
        stop(1);
    }

    int proc_slot = -1;
    Process* pNewProc = NULL;

    disableInterrupts();

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
    if (entry_point == NULL)
    {
        console_output(debugFlag, "k_spawn(): entry_point is NULL.\n");
        return -1;
    }
    if (stack_size < THREADS_MIN_STACK_SIZE)
    {
        console_output(debugFlag, "k_spawn(): stack_size %d < THREADS_MIN_STACK_SIZE.\n", stack_size);
        return -2;
    }
    if (priority < 0 || priority > HIGHEST_PRIORITY)
    {
        console_output(debugFlag, "k_spawn(): priority %d out of range.\n", priority);
        return -3;
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
        enableInterrupts();
        console_output(debugFlag, "k_spawn(): No empty slot in process table.\n");
        return -4;
    }

    pNewProc = &processTable[proc_slot];

    /* Setup the entry in the process table. (PCB initialization) */
    strcpy(pNewProc->name, name);
    pNewProc->pid = nextPid++;
    pNewProc->priority = priority;
    pNewProc->entryPoint = entry_point;
    pNewProc->args = arg;

    pNewProc->status = READY;
    pNewProc->processRunTime = 0;
    pNewProc->runTimeStart = 0;
    pNewProc->pChildren = NULL;
    pNewProc->nextSiblingProcess = NULL;
    pNewProc->nextReadyProcess = NULL;

    pNewProc->waiting = 0;
    pNewProc->waitingSignaled = 0;
    pNewProc->signaled = 0;
    pNewProc->exitCode = 0;
    pNewProc->joinTarget = -1;
    pNewProc->zombieChildren = NULL;
    pNewProc->zombieTail = NULL;

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

    /* Copies the arg string into the per-slot buffer */
    if (arg != NULL)
    {
        size_t len = strlen((char*)arg);
        if (len >= THREADS_MAX_NAME)
        {
            console_output(debugFlag, "k_spawn(): argument string too long.\n");
            enableInterrupts();
            return -1;
        }
        strcpy(argBuffer[proc_slot], (char*)arg);
        pNewProc->args = argBuffer[proc_slot];
    }
    else
    {
        pNewProc->args = NULL;
    }

    /* Initialize context for this process */
    pNewProc->context = context_initialize(launch, stack_size, pNewProc);
    if (pNewProc->context == NULL)
    {
        console_output(debugFlag, "k_spawn(): context_initialize failed.\n");
        pNewProc->pid = -1;
        pNewProc->status = EMPTY;
        enableInterrupts();
        return -1;
    }

    /* Add the process to the ready list. */
    ready_enqueue(pNewProc);

    enableInterrupts();

    if (runningProcess && pNewProc->priority >= runningProcess->priority)
    {
        dispatcher();
    }

    return pNewProc->pid;
}

/**************************************************************************
   Name - k_wait()

   Purpose - The k_wait function waits for a child process to exit and returns it’s exit code. The
             function returns when one of the caller’s child processes quits. The pid of the quitting
             process is returned by the function. For a process with more than one child, this
             function should be called once for each child process before itself calls k_exit.

   Parameters - p_child_exit_code - A pointer to an integer value that receives the exit code of
                the process.

   Returns - The function returns the pid of the quitting child upon
             successful creation. Otherwise, the return value must be one
             of the following error codes:
             pid, the PID of the process that exited
             -1 if the process has no children or zombies*
             -5 if the process was signaled in the join

   Notes - The caller does not specify a child process to wait for. The function will return after any child of the
           caller terminates. If one or more child processes has already exited when this function is called, then
           the function should return right away without waiting and with the information (pid and exit code) from
           one already terminated child. A parent process must call this function once for every child that was
           spawned to ensure the proper termination of a process and to clean up any system resources that the child
           process is or was using.
************************************************************************ */
int k_wait(int* p_child_exit_code)
{
    /* No children and no zombies to wait for, so return -1 */
    if (runningProcess->pChildren == NULL && runningProcess->zombieChildren == NULL)
    {
        return -1;
    }

    while (1)
    {
        Process* child = runningProcess->zombieChildren;

        /* Search for any zombie child */
        if (child != NULL)
        {
            /* Remove child from zombie list */
            runningProcess->zombieChildren = child->nextZombieProcess;
            if (runningProcess->zombieChildren == NULL)
            {
                runningProcess->zombieTail = NULL;
            }

            /* Saves the child pid before cleanup */
            int child_pid = child->pid;
            if (p_child_exit_code)
            {
                *p_child_exit_code = child->exitCode;
            }

            /* Cleanup child */
            cleanup_process(child);

            /* Restart start time after wait */
            runningProcess->runTimeStart = read_clock();

            /* If the process was signalled while waiting,
               return -5 instead of the child PID. */
            if (runningProcess->waitingSignaled)
            {
                runningProcess->waitingSignaled = 0;
                return -5;
            }

            return child_pid;
        }

        /* If we get here, we have children but they are not zombies, so we need to wait. */
        if (runningProcess->pChildren != NULL)
        {
            //console_output(debugFlag, "k_wait: process %d has children but no zombies, going to wait\n", runningProcess->pid); //testline
            /* Update process run time before blocking */
            runningProcess->processRunTime += (read_clock() - runningProcess->runTimeStart) / 1000;
            runningProcess->waiting = 1;
            /* Test line
            console_output(debugFlag, "k_wait: process %d is waiting for a child to quit\n", runningProcess->pid);
            display_process_table();
            display_ready_queues();
            */
            int result = block(K_WAIT);
            /*Test line
            console_output(debugFlag, "k_wait: process %d unblocked from wait with result %d\n", runningProcess->pid, result);
            display_process_table();
            display_ready_queues();
            */
            runningProcess->waiting = 0;

            /* Process was signaled while waiting */
            if (result == -5)
            {
                /* Reap a zombie child if one is already present – this
                   gives the caller the exit code of the child even
                   though the wait itself returned -5. */
                Process* zombieChild = runningProcess->zombieChildren;
                if (zombieChild != NULL)
                {
                    runningProcess->zombieChildren = zombieChild->nextZombieProcess;
                    if (runningProcess->zombieChildren == NULL)
                    {
                        runningProcess->zombieTail = NULL;
                    }
                    if (p_child_exit_code)
                    {
                        *p_child_exit_code = zombieChild->exitCode;
                    }
                    cleanup_process(zombieChild);
                }
                /* Restart start time */
                runningProcess->runTimeStart = read_clock();
                return -5;
            }
        }
    }
}

/**************************************************************************
   Name - k_join()

   Purpose - The k_join function waits for the specified process to terminate and retrieves its exit code.

   Parameters - pid, process ID of the child process to wait for
                *p_child_exit_code - A pointer to an integer value that receives the exit code of
                the process.

   Returns - 0 if Successful, -5 if the process was signaled while waiting.

   Notes - Processes cannot join with themselves and cannot join with their parent process. If the process is
           attempting to join itself or attempting to join a non-existing process, the kernel should be halted with
           an error code of 1.
           If the process attempts to join its parent, the kernel should be halted with an error code of 2.
***************************************************************************/
int k_join(int pid, int* p_child_exit_code)
{
    /* Remember which pid we are joining so that the exiting child can wake us up */
    runningProcess->joinTarget = pid;

    /* Check if trying to join self or not */
    if (pid == runningProcess->pid)
    {
        /* halts the kernel with error 0x1 */
        console_output(debugFlag, "join: process attempted to join itself.\n");
        stop(1);
    }

    /* Find process in the process table */
    Process* targetProcess = NULL;
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid == pid)
        {
            targetProcess = &processTable[i];
            break;
        }
    }

    /* Checks if trying to join nothing */
    if (targetProcess == NULL)
    {
        /* halts the kernel with error 0x1 */
        console_output(debugFlag, "join: process attempted to join non-existing process.\n");
        stop(1);
    }

    /* Do not allow joining the parent only */
    if (targetProcess == runningProcess->pParent)
    {
        console_output(debugFlag, "join: process attempted to join parent.\n");
        stop(2);
    }

    /* if child has not extied, block caller*/
    if (targetProcess->status != QUIT)
    {
        /* update process run time before blocking */
        runningProcess->processRunTime += (read_clock() - runningProcess->runTimeStart) / 1000;
        runningProcess->waiting = 1;
        runningProcess->status = K_JOIN;
        runningProcess->joinTarget = pid;
        /* Test line
        console_output(debugFlag, "k_join: process %d is joining on pid %d\n", runningProcess->pid, pid);
        display_process_table();
        display_ready_queues();
        */
        int result = block(K_JOIN);
        /* Test line
        console_output(debugFlag, "k_join: process %d unblocked from join on pid %d with result %d\n", runningProcess->pid, pid, result);
        display_process_table();
        display_ready_queues();
        */
        runningProcess->waiting = 0;

        /* if caller was signaled while waiting */
        if (result == -5)
        {
            /* Restart start time & cleanup join target */
            runningProcess->runTimeStart = read_clock();
            runningProcess->joinTarget = -1;
            return -5;
        }
    }

    /* if we get here, the child has quit and we can return the exit code */
    if (p_child_exit_code != NULL)
    {
        *p_child_exit_code = targetProcess->exitCode;
    }

    /* restart start time after wait & cleanup join target */
    runningProcess->runTimeStart = read_clock();
    runningProcess->joinTarget = -1;

    return 0;
}

/**************************************************************************
   Name - k_kill()

   Purpose - The k_kill function sends a signal to a specified process, allowing it to handle the
             signal appropriately. The only signal supported is the SIG_TERM signal defined in
             THREADS. Once a process is signaled, future calls by the process to the signaled
             function should return a 1.

   Parameters - pid, process ID of the target process
                signal, the signal to send to the process, SIG_TERM only

   Returns - 0 on success

   Notes - If the specified signal value is not SIG_TERM or if there is an attempt to signal a non-existing
           process, then the kernel should be halted with an error code of 1.
           Processes in the Scheduler do not go out of their way to terminate when signaled, this function simply
           marks the process as signaled, see the function signaled. Note the documentation in functions
           where a process is blocked and see the required return codes if a process is signaled during its wait
           time. Future iterations of the kernel use this signal to terminate user-level processes.
*************************************************************************/
int k_kill(int pid, int signal)
{
    /* Find process in the process table */
    Process* targetProcess = NULL;
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid == pid)
        {
            targetProcess = &processTable[i];
            break;
        }
    }

    /* If we can't find the process, halt kernel */
    if (targetProcess == NULL)
    {
        console_output(debugFlag, "kill: process with pid %d not found.\n", pid);
        stop(1);
    }

    /* If we have invalid signal, halt kernel */
    if (signal != SIG_TERM)
    {
        console_output(debugFlag, "kill: invalid signal %d.\n", signal);
        stop(1);
    }

    /* Marks the process as signaled */
    targetProcess->signaled = 1;
    return 0;
}

/**************************************************************************
   Name - k_exit()

   Purpose - The k_exit function terminates the calling process and sets its exit code.

   Parameters - exit_code, The processes exit code to set for the exiting child. This value
                should be overwritten to -5 when if the child process is in a
                signaled state.

   Returns - Should never do it.

   Notes - Processes cannot exit if they have one or more active child processes. If a process attempts to quit
           with an active process, then kernel should be stopped with a code of 1.
           It is important to coordinate the termination of a child process with its parent process. Note that the
           SchedulerEntryPoint and the watchdog processes do not have a parent.
*************************************************************************/
void k_exit(int exit_code)
{
    /* Test line
    console_output(FALSE, "k_exit() called for pid %d (%s)\n", runningProcess->pid, runningProcess->name);
    display_process_table();
    display_ready_queues();
    */

    /* Verifies we are in kernel mode */
    if ((get_psr() & PSR_KERNEL_MODE) == 0)
    {
        console_output(debugFlag, "Kernel mode expected, but function called in user mode.\n");
        stop(1);
    }
    if (runningProcess->pChildren != NULL && !signaled())
    {
        console_output(debugFlag, "quit(): Process with active children attempting to quit\n");
        stop(1);
    }

    /* If no more live children, quit */
    if (signaled())
    {
        exit_code = -5;
    }
    int currentRunTime = read_clock();

    /* Update process run time upon quitting */
    if (runningProcess != NULL && runningProcess->status == RUNNING)
    {
        runningProcess->processRunTime += (currentRunTime - runningProcess->runTimeStart) / 1000;
    }

    runningProcess->exitCode = exit_code;
    runningProcess->status = QUIT;

    Process* parent = runningProcess->pParent;

    /* Remove ourselves from the parent's child list and add ourselves to the parent's zombie list. */
    if (parent != NULL)
    {
        Process* prev = NULL;
        Process* current = parent->pChildren;

        while (current != NULL)
        {
            if (current == runningProcess)
            {
                if (prev == NULL)
                {
                    parent->pChildren = current->nextSiblingProcess;
                }
                else
                {
                    prev->nextSiblingProcess = current->nextSiblingProcess;
                }
                break;
            }
            prev = current;
            current = current->nextSiblingProcess;
        }

        /* Store zombie info in parent's zombie list */
        runningProcess->nextZombieProcess = NULL;

        if (parent->zombieChildren == NULL)
        {
            parent->zombieChildren = runningProcess;
            parent->zombieTail = runningProcess;
        }
        else
        {
            parent->zombieTail->nextZombieProcess = runningProcess;
            parent->zombieTail = runningProcess;
        }

        /* check if parent is blocked from wait and wake if needed */
        if (parent->waiting && parent->status == K_WAIT)
        {
            parent->waiting = 0;
            unblock(parent->pid);
        }
    }

    /* Wake up every process that is blocked in a k_join() */
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        Process* proc = &processTable[i];
        if (proc->pid != -1 && proc->status == K_JOIN && proc->joinTarget == runningProcess->pid)
        {
            //console_output(debugFlag, "k_exit: unblocking joiner pid %d for target %d\n", proc->pid, runningProcess->pid); //testline
            proc->waiting = 0;
            proc->joinTarget = -1;
            unblock(proc->pid);
        }
    }

    /* Child exiting, switch to next ready process */
    dispatcher();

    /* Should not return here */
    stop(0);
}

/**************************************************************************
   Name - k_getpid()

   Purpose - The k_getpid function returns the process ID of the calling process

   Parameters - None

   Returns - The PID of the currently running process
*************************************************************************/
int k_getpid()
{
    if (runningProcess != NULL)
    {
        return runningProcess->pid;
    }
}

/*************************************************************************
   Name - time_slice()

   Purpose - The time_slice function determines if the currently active
   process has exceeded its current time slice. If the quantum value has
   been exceeded the dispatcher is called.

   Parameters - None

   Returns - None

   Notes - The quantum is 80 ms.
*************************************************************************/
void time_slice()
{
    /* Is there a process? */
    if (runningProcess != NULL)
    {
        /* 80 ms, has time slice expired? */
        if ((read_clock() - runningProcess->runTimeStart) / 1000 >= 80)
        {
            /* timer expired, time to dispatch */
            dispatcher();
        }
    }
}

/************************************************************************
   Name - dispatcher()

   Purpose - The dispatcher function is the workhorse of the Scheduler. This is where the
             kernel decides which process to run next and changes context to the next
             process to run if context needs to change from the currently running process.

   Parameters - None

   Returns - Nothing

   NOTES:
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
    uint32_t currentRunTime = read_clock();

    if (runningProcess != NULL && runningProcess->status == RUNNING)
    {
        /* Add CPU time of current process */
        runningProcess->processRunTime += (currentRunTime - runningProcess->runTimeStart) / 1000;

        int preempt = 0;
        for (int prio = 5; prio >= runningProcess->priority; prio--)
        {
            if (ready_queues[prio] != NULL)
            {
                preempt = 1;
                break;
            }
        }
        if (preempt != 1)
        {
            /* reset start time for currently running process */
            runningProcess->runTimeStart = currentRunTime;
            return;
        }

        /* If we get here, we need to preempt the current process because an equal or higher prio was found */
        runningProcess->status = READY;
        ready_enqueue(runningProcess);
    }

    /* Get next process to run*/
    Process* nextProcess = ready_dequeue();

    if (nextProcess != NULL)
    {
        runningProcess = nextProcess;
        runningProcess->status = RUNNING;

        /* Reset start time for this process */
        runningProcess->runTimeStart = currentRunTime;

        /* IMPORTANT: context switch enables interrupts. */
        context_switch(runningProcess->context);
    }
    else
    {
        /* If we get here, no process is ready and we need the watchdog*/
        return;
    }
}

/*************************************************************************
   Name - signaled()

   Purpose - Checks whether the current process has been signaled

   Parameters - None

   Returns - 1 if signaled, 0 if otherwise

   Side Effects/Use Cases - Used by k_wait(), k_join(), and block()
*************************************************************************/
int signaled()
{
    if (runningProcess->signaled)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/*************************************************************************
   Name - block()

   Purpose - This function blocks the calling process and sets the processes status in the process
                table to the value specified in block_status. The value of block_status must be
                greater than 10. The values of 0-10 are reserved for internal kernel process states.

   Parameters - block_status for the block status to be assigned to the blocked process

   Returns - -5 if signaled while blocked
             0 on successful new process creation

   Notes - If this function is called with a value equal to or less than 10, the kernel should be halted with a code of 1:
            Use integer values 0-10 to keep track of the state of processes in the process table.

*************************************************************************/
int block(int block_status)
{
    /* Validate arguments */
    if (block_status <= 10)
    {
        console_output(debugFlag, "block: function called with a reserved status value.\n", block_status);
        stop(1);
    }

    /* Was the process signaled? */
    if (signaled())
    {
        /* If we are about to block on a wait, remember that we were
           signalled while waiting – we still block normally. */
        if (block_status == K_WAIT)
        {
            runningProcess->waitingSignaled = 1;
        }
        else
        {
            /* For a join we return -5 immediately */
            return -5;
        }
    }

    /* Assign status to K_WAIT */
    runningProcess->status = block_status;

    /* Keep dispatching until process is unblocked */
    dispatcher();

    if (signaled())
    {
        if (block_status == K_WAIT)
        {
            /* We intentionally do NOT return -5 – we already set
               waitingSignaled above and will return -5 after the
               wait completes. */
            return 0;
        }

        return -5;
    }

    /* 0 on success, new process created */
    return 0;
}

/**************************************************************************
   Name - unblock()

   Purpose - The unblock function returns a blocked process to the ready to run state.

   Parameters - pid, the process ID of the process to unblock.

   Retruns - The function returns 0 upon success. Otherwise, an error
             code is returned.
             0 - Success
             -1 - The process specified by pid is not valid or is not blocked.

*************************************************************************/
int unblock(int pid)
{
    /* Find process in the process table */
    Process* targetProcess = NULL;

    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid == pid)
        {
            targetProcess = &processTable[i];
            break;
        }
    }

    /* Checks if process exists, if not return -1 */
    if (targetProcess == NULL)
    {
        return -1;
    }

    /* If process is not blocked, return -1 */
    if (targetProcess->status <= 10)
    {
        return -1;
    }

    /* Unblock the process */
    targetProcess->status = READY;

    /* Send to the queue */
    ready_enqueue(targetProcess);
    return 0;
}

/*************************************************************************
   Name - get_start_time()

   Purpose - This function returns the start time of the process in microseconds.

   Parameters - None

   Returns - The function returns the calling process’s start time.

   Notes - Halts the kernel if illegally called
*************************************************************************/
int get_start_time()
{
    /* Is a process running? */
    if (runningProcess != NULL)
    {
        if (runningProcess->runTimeStart == 0)
        {
            /* Reads clock and divides by 1000 for time in ms */
            runningProcess->runTimeStart = read_clock();
        }
        return runningProcess->runTimeStart;
    }
    else
    {
        /* Halts the kernel, no running process, this is illegal */
        console_output(debugFlag, "get_start_time(): invalid behavior, no runningProcess. Halting kernel...\n");
        stop(1);
    }
}

/*************************************************************************
   Name - cpu_time()/read_time() naming convention as required by test30

   Purpose - The cpu_time function returns the amount of time in milliseconds that the
                current process has spent on the CPU.

   Parameters - None

   Returns - The function returns the calling process’s cpu time

   Notes - Halts the kernel with illegal activity
*************************************************************************/
int read_time()
{
    /* If running process is null stop the kernel */
    if (runningProcess == NULL)
    {
        console_output(debugFlag, "read_time(): invalid behavior, no runningProcess. Halting kernel...\n");
        stop(1);
    }
    if (runningProcess != NULL)
    {
        /* Current time program has been running in ms */
        int currentRunTime = read_clock();

        /* ms conversion */
        int currentProcessTime = (currentRunTime - runningProcess->runTimeStart) / 1000;

        /* Return run time of currently running process in ms */
        return runningProcess->processRunTime + currentProcessTime;
    }
}

/*************************************************************************
   Name - read_clock()

   Purpose - This function returns the current value of the system clock using the THREADS system_clock function.

   Parameters - None

   Returns - The function returns the value of system_clock.
*************************************************************************/
uint32_t read_clock()
{
    return system_clock();
}

/**************************************************************************
   Name - status_name()

   Purpose - This function is a helper to convert status numbers to their correct strings

   Parameters - None

   Returns - The correct string
*************************************************************************/
const char* status_name(int st) {
    switch (st) {
    case EMPTY:   return "EMPTY";
    case READY:   return "READY";
    case RUNNING: return "RUNNING";
    case BLOCKED: return "BLOCKED";
    case QUIT:    return "QUIT";
    case JOINED:  return "JOINED";
    case K_WAIT:  return "WAIT BLOCK";
    case K_JOIN:  return "JOIN BLOCK";
    case 14:      return "14";
    default:      return "UNKNOWN";
    }
}

/**************************************************************************
   Name - display_process_table()

   Purpose - This function displays all non-empty processes in the process table. The displayed
            information includes the process Id (PID), parent PID, Priority, status, number of
            children, cpu time, and process name.

   Parameters - None

   Returns - None
*************************************************************************/
void display_process_table()
{
    /* Title for table print */
    console_output(debugFlag, "PID     Parent   Priority  Status        # Kids   CPUtime  Name    \n");
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        /* Handles parent PID */
        int parentPID = -1;
        if (processTable[i].pid != -1)
        {
            if (processTable[i].pParent != NULL)
            {
                parentPID = processTable[i].pParent->pid;
            }
        }

        /* Handles child PID */
        int numChildren = 0;
        Process* child = processTable[i].pChildren;
        while (child != NULL)
        {
            numChildren++;
            child = child->nextSiblingProcess;
        }
        /* Get CPU time */
        int currentRunTime = processTable[i].processRunTime;

        /* If the process is currently running, get current time */
        if (runningProcess != NULL && processTable[i].pid == runningProcess->pid)
        {
            currentRunTime += (read_clock() - runningProcess->runTimeStart) / 1000;
        }
        if (processTable[i].pid != -1)
        {
            console_output(debugFlag, "%-5d   %-6d   %-7d   %-11s   %-6d   %-7d  %s\n", processTable[i].pid, parentPID, processTable[i].priority, status_name(processTable[i].status), numChildren, currentRunTime, processTable[i].name);
        }
    }
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
    int done = 1;
    /* Begin indexing after watchdog, and if its the only process left, stop on 0. */
    for (int i = 1; i < MAX_PROCESSES; i++)
    {
        /* Check if watchdog is the only process running */
        if (processTable[i].pid != -1)
        {
            int stat = processTable[i].status;
            /* Checks if a process is finished */
            if (stat != EMPTY && stat != QUIT && stat != JOINED && stat != K_WAIT && stat != K_JOIN)
            {
                done = 0;
                break;
            }
        }
    }

    if (done == 1)
    {
        console_output(debugFlag, "All processes completed.\n");
        stop(0);
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
   Name - clock_handler()

   Purpose - Handles the timer interrupt.

   Parameters - char *deviceName, uint8_t command, uint32_t status

   Returns - None
*************************************************************************/
static void clock_handler(char* deviceName, uint8_t command, uint32_t status)
{
    time_slice();
}

/**************************************************************************
   Name - ready_queue_init()

   Purpose - Initializes all ready queues to empty. This function must be
   called before any process is enqueued.

   Parameters - None

   Returns - Nothing
*************************************************************************/
void ready_queue_init(void)
{
    for (int i = 0; i < NUM_PRIORITIES; i++)
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
    /* Dequeues from highest priority queue first */
    for (int prio = NUM_PRIORITIES - 1; prio >= 0; prio--)
    {
        /* If queue is not empty get process at head and update the head for the next process */
        if (ready_queues[prio] != NULL)
        {
            Process* p = ready_queues[prio];
            ready_queues[prio] = p->nextReadyProcess;

            /* Clear the next pointer of the dequeued process */
            p->nextReadyProcess = NULL;
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
void display_ready_queues(void)
{
    console_output(debugFlag, "\nREADY QUEUES:\n");
    for (int prio = 0; prio < NUM_PRIORITIES; prio++)
    {
        console_output(debugFlag, "Priority %d: ", prio);
        Process* current = ready_queues[prio];

        if (current == NULL)
        {
            console_output(debugFlag, "EMPTY\n");
            continue;
        }

        while (current != NULL)
        {
            console_output(debugFlag, "[PID=%d %s] -> ", current->pid, current->name);
            current = current->nextReadyProcess;
        }

        console_output(debugFlag, "NULL\n");
    }
}

/**************************************************************************
   Name - launch()

   Purpose - Utility function that makes sure the environment is ready,
             such as enabling interrupts, for the new process.

   Parameters - Pointer to the process to launch

   Returns - nothing
*************************************************************************/
static int launch(void* args)
{
    /* Enable interrupts */
    enableInterrupts();

    /* Call the function passed to spawn and capture its return value */
    int rc = runningProcess->entryPoint(runningProcess->args);

    /* Stop the process gracefully */
    k_exit(rc);

    return 0;
}

/**************************************************************************
   Name - check_io_scheduler()

   Purpose - Checks IO. Since it is not implemented it returns false.

   Parameters - None

   Returns - False
*************************************************************************/
int check_io_scheduler()
{
    return false;
}

/*************************************************************************
Name void cleanup_process(Process* proc)

Purpose - This function cleans up the process's resources and resets its PCB entry.

Parameters - proc, the process to clean up

Returns - Nothing
*************************************************************************/
void cleanup_process(Process* proc)
{
    /* Reset the PCB */
    proc->pid = -1;
    proc->context = NULL;
    proc->pParent = NULL;
    proc->pChildren = NULL;
    proc->nextReadyProcess = NULL;
    proc->nextSiblingProcess = NULL;
    proc->nextZombieProcess = NULL;
    proc->args = NULL;
    proc->entryPoint = NULL;
    proc->context = NULL;
    proc->priority = 0;
    proc->processRunTime = 0;
    proc->exitCode = 0;
    proc->waiting = 0;
    proc->waitingSignaled = 0;
    proc->signaled = 0;
    proc->status = EMPTY;
    proc->joinTarget = -1;
    proc->zombieChildren = NULL;
    proc->zombieTail = NULL;
}
