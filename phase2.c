#include <phase1.h>
#include <phase2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Data Structures
typedef struct ShadowProcess
{
    int pid;

    struct ShadowProcess *consumer_queue_next;
    struct ShadowProcess *producer_queue_next;
} ShadowProcess;

typedef struct MailSlot
{
    int mailbox_id;
    int claimed_by_pid;

    int message_size;
    char message[MAX_MESSAGE];

    struct MailSlot *queue_next;
} MailSlot;

typedef struct MailBox
{
    short in_use;
    short flagged_for_removal;

    int used_slots;
    int max_slots;
    int slot_size;

    MailSlot *slot_queue;
    ShadowProcess *consumer_queue;
    ShadowProcess *producer_queue;
} MailBox;

static MailBox mailboxes[MAXMBOX];
static MailSlot mailslots[MAXSLOTS];
static ShadowProcess shadow_table[MAXPROC];

static int last_clock_time = 0;
static int clock_mbox;
static int disk_mboxes[2];
static int terminal_mboxes[4];

int next_mbox_id = 0;

// Helper Functions
void check_kernel_mode(const char *function_name)
{
    if ((USLOSS_PsrGet() & USLOSS_PSR_CURRENT_MODE) == 0)
    {
        USLOSS_Console("ERROR: Someone attempted to call %s while in user mode!\n", function_name);
        USLOSS_Halt(1);
    }
}

int disable_interrupts()
{
    int old_psr = USLOSS_PsrGet();
    USLOSS_PsrSet(USLOSS_PsrGet() & ~USLOSS_PSR_CURRENT_INT);
    return old_psr;
}

int is_valid_mailbox_id(int mbox_id)
{
    if (mbox_id < 0 || mbox_id >= MAXMBOX)
        return 0;

    return mailboxes[mbox_id].in_use;
}

int get_next_free_mailbox_slot()
{
    for (int i = 0; i < MAXSLOTS; i++)
        if (mailslots[i].mailbox_id == -1)
            return i;
    return -1;
}

// Phase 2 Device Helpers
int getDeviceMailbox(int type, int unit)
{
    if(type == USLOSS_CLOCK_DEV) return clock_mbox;
    else if (type == USLOSS_DISK_DEV) return disk_mboxes[unit];
    else if (type == USLOSS_TERM_DEV) return terminal_mboxes[unit];
    else return -1;
}

static void clock_interrupt_handler(int type, void *payload)
{
    int current_time = currentTime() / 1000; // Call to get the current clock time in ms.
    // USLOSS_Console("Clock interrupt at time %d\n", current_time);

    if (current_time - last_clock_time >= 100)
    {
        // USLOSS_Console("SENDING MESSAGE at time %d\n", current_time);
        // int res =
        MboxCondSend(clock_mbox, &current_time, sizeof(int)); // Send current time.
        // USLOSS_Console("MboxCondSend returned %d\n", res);
        last_clock_time = current_time;
    }
    dispatcher(); // Dispatcher call required.
}

void disk_interrupt_handler(int type, void *payload)
{
    int unit = (int)(long)payload; // Extract unit number from payload.
    int status;

    status = USLOSS_DeviceInput(USLOSS_DISK_DEV, unit, &status); // Get current status of the disk.

    MboxCondSend(disk_mboxes[unit], &status, sizeof(int)); // Send status to the corresponding disk mailbox.

    dispatcher();
}

void terminal_interrupt_handler(int type, void *payload)
{
    int unit = (int)(long)payload; // Extract unit number from payload.
    int status;

    status = USLOSS_DeviceInput(USLOSS_TERM_DEV, unit, &status); // Get current status of the disk.

    MboxCondSend(terminal_mboxes[unit], &status, sizeof(int)); // Send status to the corresponding disk mailbox.

    dispatcher();
}

// void syscall_interrupt_handler(int type, void *payload)
// {
//     USLOSS_Sysargs *args = (USLOSS_Sysargs *)payload;
//     systemCallVec[args->number](args);
// }

void nullsys()
{
    USLOSS_Console("nullsys(): error\n");
    USLOSS_Halt(1);
}

// Mailbox Helpers

// Marks the first mail slot for delivery to the first consumer in queue
// Called with the assumption that the mailbox has at least one consumer
void deliver_first_message(MailBox* mailbox)
{
    // Remove first consumer from queue
    ShadowProcess *consumer = mailbox->consumer_queue;
    mailbox->consumer_queue = consumer->consumer_queue_next;

    // Set the first unclaimed slot in the queue to be claimed by the first consumer
    // Does not remove the slot from the queue, that is done in MboxRecv()
    // Hopefully avoids the race condition
    MailSlot *deliver_slot = mailbox->slot_queue;
    while (deliver_slot->claimed_by_pid)
        deliver_slot = deliver_slot->queue_next;
    deliver_slot->claimed_by_pid = consumer->pid;

    // Unblock consumer, it will eventually grab this message
    unblockProc(consumer->pid);
}


// Phase 2 Spec Functions

void phase2_init(void)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Clear out all mailboxes, slots, and shadow process table
    memset(mailboxes, 0, sizeof(mailboxes));
    memset(mailslots, 0, sizeof(mailslots));
    memset(shadow_table, 0, sizeof(shadow_table));

    // Set mailslot mailbox_id to -1 to indicate it's free
    for (int i = 0; i < MAXSLOTS; i++)
        mailslots[i].mailbox_id = -1;

    // Create device mailboxes
    clock_mbox = MboxCreate(1, sizeof(int));

    for (int i = 0; i < 2; i++)
        disk_mboxes[i] = MboxCreate(1, sizeof(int));

    for (int i = 0; i < 4; i++)
        terminal_mboxes[i] = MboxCreate(1, sizeof(int));

    USLOSS_IntVec[USLOSS_CLOCK_INT] = clock_interrupt_handler;
    USLOSS_IntVec[USLOSS_DISK_INT] = disk_interrupt_handler;
    USLOSS_IntVec[USLOSS_TERM_INT] = terminal_interrupt_handler;
    // USLOSS_IntVec[USLOSS_SYSCALL_INT] = syscall_interrupt_handler;

    // define systemcallvec
    void (*systemCallVec[MAXSYSCALLS])(USLOSS_Sysargs *args);

    for (int i = 0; i < MAXSYSCALLS; i++)
    {
        systemCallVec[i] = nullsys;
    }

    USLOSS_PsrSet(old_psr);
}

// returns id of mailbox, or -1 if no more mailboxes, or -1 if invalid args
int MboxCreate(int slots, int slot_size)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    if (slots < 0 || slot_size < 0)
        return -1; // Negative slots or slot_size

    // Find next available mailbox
    int init_mbox_id = next_mbox_id++ % MAXMBOX;
    MailBox *mbox = &mailboxes[init_mbox_id];
    while (mbox->in_use)
    {
        if (next_mbox_id % MAXMBOX == init_mbox_id)
            return -1; // No free mailboxes

        mbox = &mailboxes[next_mbox_id++ % MAXMBOX];
    }

    // Reset mailbox in case there's left over data
    memset(mbox, 0, sizeof(MailBox));

    // Mailbox initialization
    mbox->in_use = 1;
    mbox->max_slots = slots;
    mbox->slot_size = slot_size;

    USLOSS_PsrSet(old_psr);
    return next_mbox_id - 1;
}

// returns 0 if successful, -1 if invalid arg
int MboxRelease(int mbox_id)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Check if mbox_id is valid
    if (!is_valid_mailbox_id(mbox_id))
        return -1;

    MailBox *mailbox = &mailboxes[mbox_id];

    // Flag for removal in case a Context Switch occurs
    mailbox->flagged_for_removal = 1;

    // Release slots
    MailSlot *slot = mailbox->slot_queue;
    while (slot != NULL)
    {
        MailSlot *next = slot->queue_next;
        memset(slot, 0, sizeof(MailSlot));
        slot->mailbox_id = -1;
        slot = next;
    }

    // Wake up consumer queue processes
    ShadowProcess *consumer = mailbox->consumer_queue;
    while (consumer != NULL)
    {
        unblockProc(consumer->pid);
        consumer = consumer->consumer_queue_next;
    }

    // Wake up producer queue processes
    ShadowProcess *producer = mailbox->producer_queue;
    while (producer != NULL)
    {
        unblockProc(producer->pid);
        producer = producer->producer_queue_next;
    }

    // Clear out mailbox
    memset(mailbox, 0, sizeof(MailBox));

    USLOSS_PsrSet(old_psr);
    return 0;
}

// returns 0 if successful, -1 if invalid args
int MboxSend(int mbox_id, void *msg_ptr, int msg_size)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Check if mbox_id is valid
    if (!is_valid_mailbox_id(mbox_id))
        return -1;

    MailBox *mailbox = &mailboxes[mbox_id];

    if (mailbox->flagged_for_removal)
        return -1;                                      // Mailbox is flagged for removal
    else if (mailbox->used_slots == mailbox->max_slots) // Mailbox is full, add process to producer queue
    {
        ShadowProcess *process = &shadow_table[getpid() % MAXPROC];

        // Add process to producer queue
        if (mailbox->producer_queue == NULL)
            mailbox->producer_queue = process;
        else
        {
            ShadowProcess *last_process = mailbox->producer_queue;
            while (last_process->producer_queue_next != NULL)
                last_process = last_process->producer_queue_next;
            last_process->producer_queue_next = process;
        }

        // Block (when the mailbox has space it'll unblock)
        blockMe();
    }

    int slot_index = get_next_free_mailbox_slot();

    if (slot_index == -1)
        return -2; // No global free slots

    // Copy message into slot
    MailSlot *slot = &mailslots[slot_index];
    slot->mailbox_id = mbox_id;
    memcpy(slot->message, msg_ptr, msg_size);
    slot->message_size = msg_size;

    // Add slot to mailbox
    MailSlot *last_slot = mailbox->slot_queue;
    if (last_slot == NULL)
        mailbox->slot_queue = slot;
    else
    {
        while (last_slot->queue_next != NULL)
            last_slot = last_slot->queue_next;
        last_slot->queue_next = slot;
    }

    printf("First consumer: %p\n", mailbox->consumer_queue);

    // If there are consumers, mark this slot for delivery to the first one and wake it up
    if (mailbox->consumer_queue != NULL)
        deliver_first_message(mailbox);

    USLOSS_PsrSet(old_psr);
    return 0;
}

// returns size of received msg if successful, -1 if invalid args
int MboxRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    if (!is_valid_mailbox_id(mbox_id))
        return -1; // Invalid mailbox id

    MailBox *mailbox = &mailboxes[mbox_id];

    if (mailbox->flagged_for_removal)
        return -1; // Mailbox is flagged for removal

    // Search for a claimed slot, or the first unclaimed slot
    MailSlot *prev = NULL;
    MailSlot *slot = mailbox->slot_queue;
    while (slot != NULL)
    {
        // Deliverable slot found if claimed by current process or unclaimed by any
        // Break out of loop if so to actually deliver the message
        if (slot->claimed_by_pid == getpid() || !slot->claimed_by_pid)
            break;

        prev = slot;
        slot = slot->queue_next;
    }

    // If no deliverable slot found, add the current process to the consumer queue and block
    if (slot == NULL)
    {
        ShadowProcess *current = &shadow_table[getpid() % MAXPROC];
        if (mailbox->consumer_queue == NULL)
            mailbox->consumer_queue = current;
        else
        {
            ShadowProcess *last = mailbox->consumer_queue;
            while (last->consumer_queue_next != NULL)
                last = last->consumer_queue_next;
            last->consumer_queue_next = current;
        }

        blockMe();
    }

    // Remove slot from mailbox
    if (prev == NULL)
        mailbox->slot_queue = slot->queue_next;
    else
        prev->queue_next = slot->queue_next;

    // Message too large for buffer
    if (slot->message_size > msg_max_size)
    {
        memset(slot, 0, sizeof(MailSlot));
        return -1;
    }

    // Copy message into buffer
    memcpy(msg_ptr, slot->message, slot->message_size);

    // Free slot
    int return_size = slot->message_size;
    memset(slot, 0, sizeof(MailSlot));
    slot->mailbox_id = -1;

    // Unblock a producer, if any, are waiting
    if (mailbox->producer_queue != NULL)
    {
        ShadowProcess *producer = mailbox->producer_queue;
        mailbox->producer_queue = producer->producer_queue_next;
        unblockProc(producer->pid);
    }

    USLOSS_PsrSet(old_psr);
    return return_size;
}

// returns 0 if successful, 1 if mailbox full, -1 if illegal args
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Check if mbox_id is valid
    if (!is_valid_mailbox_id(mbox_id))
        return -1;

    MailBox *mailbox = &mailboxes[mbox_id];

    if (mailbox->flagged_for_removal)
        return -1;                                      // Mailbox is flagged for removal
    else if (mailbox->used_slots == mailbox->max_slots) // Mailbox is full, add process to producer queue
    {
        ShadowProcess *process = &shadow_table[getpid() % MAXPROC];

        // Add process to producer queue
        if (mailbox->producer_queue == NULL)
            mailbox->producer_queue = process;
        else
        {
            ShadowProcess *last_process = mailbox->producer_queue;
            while (last_process->producer_queue_next != NULL)
                last_process = last_process->producer_queue_next;
            last_process->producer_queue_next = process;
        }

        // Would normally block, but returns -2
        return -2;
    }

    int slot_index = get_next_free_mailbox_slot();

    if (slot_index == -1)
        return -2; // No global free slots

    // Copy message into slot
    MailSlot *slot = &mailslots[slot_index];
    slot->mailbox_id = mbox_id;
    memcpy(slot->message, msg_ptr, msg_size);
    slot->message_size = msg_size;

    // Add slot to mailbox
    MailSlot *last_slot = mailbox->slot_queue;
    if (last_slot == NULL)
        mailbox->slot_queue = slot;
    else
    {
        while (last_slot->queue_next != NULL)
            last_slot = last_slot->queue_next;
        last_slot->queue_next = slot;
    }

    // If there are consumers, mark this slot for delivery to the first one and wake it up
    if (mailbox->consumer_queue != NULL)
        deliver_first_message(mailbox);

    USLOSS_PsrSet(old_psr);
    return 0;
}

// returns 0 if successful, 1 if no msg available, -1 if illegal args
int MboxCondRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    if (!is_valid_mailbox_id(mbox_id))
        return -1; // Invalid mailbox id

    MailBox *mailbox = &mailboxes[mbox_id];

    if (mailbox->flagged_for_removal)
        return -1; // Mailbox is flagged for removal

    // Search for a claimed slot, or the first unclaimed slot
    MailSlot *prev = NULL;
    MailSlot *slot = mailbox->slot_queue;
    while (slot != NULL)
    {
        // Deliverable slot found if claimed by current process or unclaimed by any
        // Break out of loop if so to actually deliver the message
        if (slot->claimed_by_pid == getpid() || !slot->claimed_by_pid)
            break;

        prev = slot;
        slot = slot->queue_next;
    }

    // If no deliverable slot found, add the current process to the consumer queue and block
    if (slot == NULL)
    {
        ShadowProcess *current = &shadow_table[getpid() % MAXPROC];
        if (mailbox->consumer_queue == NULL)
            mailbox->consumer_queue = current;
        else
        {
            ShadowProcess *last = mailbox->consumer_queue;
            while (last->consumer_queue_next != NULL)
                last = last->consumer_queue_next;
            last->consumer_queue_next = current;
        }

        return -2; // Would be a block
    }

    // Remove slot from mailbox
    if (prev == NULL)
        mailbox->slot_queue = slot->queue_next;
    else
        prev->queue_next = slot->queue_next;

    // Message too large for buffer
    if (slot->message_size > msg_max_size)
    {
        memset(slot, 0, sizeof(MailSlot));
        return -1;
    }

    // Copy message into buffer
    memcpy(msg_ptr, slot->message, slot->message_size);

    // Free slot
    int return_size = slot->message_size;
    memset(slot, 0, sizeof(MailSlot));
    slot->mailbox_id = -1;

    // Unblock a producer, if any, are waiting
    if (mailbox->producer_queue != NULL)
    {
        ShadowProcess *producer = mailbox->producer_queue;
        mailbox->producer_queue = producer->producer_queue_next;
        unblockProc(producer->pid);
    }

    USLOSS_PsrSet(old_psr);
    return return_size;
}

// type = interrupt device type, unit = # of device (when more than one),
// status = where interrupt handler puts device's status register.
void waitDevice(int type, int unit, int *status)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Validate type and unit arguments
    if ((type != USLOSS_CLOCK_DEV && type != USLOSS_DISK_DEV && type != USLOSS_TERM_DEV) ||
        (type == USLOSS_CLOCK_DEV && unit != 0) ||
        (type == USLOSS_DISK_DEV && (unit < 0 || unit > 1)) ||
        (type == USLOSS_TERM_DEV && (unit < 0 || unit > 3)))
    {
        USLOSS_Console("Error: Invalid device type or unit.\n");
        USLOSS_Halt(1); // Halt the simulation on error
    }

    int mailboxID = getDeviceMailbox(type, unit); // Retrieve the corresponding mailbox
    int message;

    // Block and wait for the interrupt to send a message to the mailbox
    if (MboxRecv(mailboxID, &message, sizeof(int)) < 0)
    {
        USLOSS_Console("Error: MboxRecv failed in waitDevice.\n");
        USLOSS_Halt(1);
    }

    // Store the received device status in the out parameter
    *status = message;

    USLOSS_PsrSet(old_psr);
}

void wakeupByDevice(int type, int unit, int status)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Validate type and unit arguments (similar to waitDevice)
    if ((type != USLOSS_CLOCK_DEV && type != USLOSS_DISK_DEV && type != USLOSS_TERM_DEV) ||
        (type == USLOSS_CLOCK_DEV && unit != 0) ||
        (type == USLOSS_DISK_DEV && (unit < 0 || unit > 1)) ||
        (type == USLOSS_TERM_DEV && (unit < 0 || unit > 3)))
    {
        USLOSS_Console("Error: Invalid device type or unit in wakeupByDevice.\n");
        return; // Just return; it's not necessary to halt in this case.
    }

    int mailboxID = getDeviceMailbox(type, unit); // Retrieve the corresponding mailbox

    // Attempt to send the status to the mailbox without blocking
    int result = MboxCondSend(mailboxID, &status, sizeof(int));

    if (result == -2)
    {
        // This indicates that the mailbox is full, but we won't block or halt the system
        USLOSS_Console("Warning: MboxCondSend failed due to full mailbox in wakeupByDevice.\n");
    }
    else if (result < 0)
    {
        USLOSS_Console("Error: MboxCondSend failed in wakeupByDevice.\n");
        USLOSS_Halt(1);
    }

    USLOSS_PsrSet(old_psr);
}

void phase2_start_service_processes(void)
{
    // Unused for this phase
}