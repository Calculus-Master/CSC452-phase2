#include <phase1.h>
#include <phase2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Data Structures
typedef struct ShadowProcess {
    int pid;

    struct ShadowProcess* consumer_queue_next;
    struct ShadowProcess* producer_queue_next;
} ShadowProcess;

typedef struct MailSlot {
    int mailbox_id;
    int claimed_by_pid;

    int message_size;
    char message[MAX_MESSAGE];

    struct MailSlot* queue_next;
} MailSlot;

typedef struct MailBox {
    short in_use;
    short flagged_for_removal;

    int used_slots;
    int max_slots;
    int slot_size;

    MailSlot* slot_queue;
    ShadowProcess* consumer_queue;
    ShadowProcess* producer_queue;
} MailBox;

static MailBox mailboxes[MAXMBOX];
static MailSlot mailslots[MAXSLOTS];
static ShadowProcess shadow_table[MAXPROC];

next_mbox_id = 0;

// Helper Functions
void check_kernel_mode(const char *function_name)
{
    if ((USLOSS_PsrGet() & USLOSS_PSR_CURRENT_MODE) == 0)
    {
        USLOSS_Console("ERROR: Someone attempted to call %s while in user mode!\n", function_name);
        USLOSS_Halt(1);
    }
}

int is_valid_mailbox_id(int mbox_id)
{
    if(mbox_id < 0 || mbox_id >= MAXMBOX)
        return 0;

    return mailboxes[mbox_id].in_use;
}

int get_next_free_mailbox_slot()
{
    for(int i = 0; i < MAXSLOTS; i++)
        if(mailslots[i].mailbox_id == -1)
            return i;
    return -1;
}

// Phase 2 Functions

void phase2_init(void)
{
    // Clear out all mailboxes, slots, and shadow process table
    memset(mailboxes, 0, sizeof(mailboxes));
    memset(mailslots, 0, sizeof(mailslots));
    memset(shadow_table, 0, sizeof(shadow_table));

    // Set mailslot mailbox_id to -1 to indicate it's free
    for(int i = 0; i < MAXSLOTS; i++)
        mailslots[i].mailbox_id = -1;

    // Create device mailboxes
    // TODO idk how these get used, but they probably need to be stored somewhere
    int clock1_mbox = MboxCreate(1, sizeof(int));
    int disk1_mbox = MboxCreate(1, sizeof(int));
    int disk2_mbox = MboxCreate(1, sizeof(int));
    int term1_mbox = MboxCreate(1, sizeof(int));
    int term2_mbox = MboxCreate(1, sizeof(int));
    int term3_mbox = MboxCreate(1, sizeof(int));
    int term4_mbox = MboxCreate(1, sizeof(int));
}

// returns id of mailbox, or -1 if no more mailboxes, or -1 if invalid args
int MboxCreate(int slots, int slot_size)
{
    check_kernel_mode(__func__ );

    if(slots < 0 || slot_size < 0)
        return -1; // Negative slots or slot_size

    // Find next available mailbox
    int init_mbox_id = next_mbox_id++ % MAXMBOX;
    MailBox* mbox = &mailboxes[init_mbox_id];
    while(mbox->in_use)
    {
        if(next_mbox_id % MAXMBOX == init_mbox_id)
            return -1; // No free mailboxes

        mbox = &mailboxes[next_mbox_id++ % MAXMBOX];
    }

    // Reset mailbox in case there's left over data
    memset(mbox, 0, sizeof(MailBox));

    // Mailbox initialization
    mbox->in_use = 1;
    mbox->max_slots = slots;
    mbox->slot_size = slot_size;

    return next_mbox_id - 1;
}

// returns 0 if successful, -1 if invalid arg
int MboxRelease(int mbox_id)
{
    check_kernel_mode(__func__ );

    // Check if mbox_id is valid
    if(!is_valid_mailbox_id(mbox_id))
        return -1;

    MailBox* mailbox = &mailboxes[mbox_id];

    // Flag for removal in case a Context Switch occurs
    mailbox->flagged_for_removal = 1;

    // Release slots
    MailSlot* slot = mailbox->slot_queue;
    while(slot != NULL)
    {
        MailSlot* next = slot->queue_next;
        memset(slot, 0, sizeof(MailSlot));
        slot->mailbox_id = -1;
        slot = next;
    }

    // Wake up consumer queue processes
    ShadowProcess* consumer = mailbox->consumer_queue;
    while(consumer != NULL)
    {
        unblockProc(consumer->pid);
        consumer = consumer->consumer_queue_next;
    }

    // Wake up producer queue processes
    ShadowProcess* producer = mailbox->producer_queue;
    while(producer != NULL)
    {
        unblockProc(producer->pid);
        producer = producer->producer_queue_next;
    }

    // Clear out mailbox
    memset(mailbox, 0, sizeof(MailBox));

    return 0;
}

// returns 0 if successful, -1 if invalid args
int MboxSend(int mbox_id, void *msg_ptr, int msg_size)
{
    check_kernel_mode(__func__ );

    // Check if mbox_id is valid
    if(!is_valid_mailbox_id(mbox_id))
        return -1;

    MailBox* mailbox = &mailboxes[mbox_id];

    if(mailbox->flagged_for_removal)
        return -1; // Mailbox is flagged for removal
    else if(mailbox->used_slots == mailbox->max_slots) // Mailbox is full, add process to producer queue
    {
        ShadowProcess* process = &shadow_table[getpid() % MAXPROC];

        // Add process to producer queue
        if(mailbox->producer_queue == NULL)
            mailbox->producer_queue = process;
        else
        {
            ShadowProcess* last_process = mailbox->producer_queue;
            while(last_process->producer_queue_next != NULL)
                last_process = last_process->producer_queue_next;
            last_process->producer_queue_next = process;
        }

        // Block (when the mailbox has space it'll unblock)
        blockMe();
    }

    int slot_index = get_next_free_mailbox_slot();

    if(slot_index == -1)
        return -2; // No global free slots

    // Copy message into slot
    MailSlot* slot = &mailslots[slot_index];
    slot->mailbox_id = mbox_id;
    memcpy(slot->message, msg_ptr, msg_size);
    slot->message_size = msg_size;

    // Add slot to mailbox
    MailSlot* last_slot = mailbox->slot_queue;
    if(last_slot == NULL)
        mailbox->slot_queue = slot;
    else
    {
        while(last_slot->queue_next != NULL)
            last_slot = last_slot->queue_next;
        last_slot->queue_next = slot;
    }

    // If no consumers, block
    if(mailbox->consumer_queue == NULL)
        blockMe();

    // Wake up a consumer and mark a slot for delivery (if it blocks in the previous step, should CS to this line)
    // TODO: PROBABLY BUGGY
    // Remove first consumer from queue
    ShadowProcess* consumer = mailbox->consumer_queue;
    mailbox->consumer_queue = consumer->consumer_queue_next;

    // Set the first unclaimed slot in the queue to be claimed by the first consumer
    // Does not remove the slot from the queue, that is done in MboxRecv()
    // Hopefully avoids the race condition
    MailSlot* deliver_slot = mailbox->slot_queue;
    while(deliver_slot->claimed_by_pid)
        deliver_slot = deliver_slot->queue_next;
    deliver_slot->claimed_by_pid = consumer->pid;

    // Unblock consumer, it will eventually grab this message
    unblockProc(consumer->pid);
    return 0;
}

// returns size of received msg if successful, -1 if invalid args
int MboxRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{
    check_kernel_mode(__func__ );

    if(!is_valid_mailbox_id(mbox_id))
        return -1; // Invalid mailbox id

    MailBox* mailbox = &mailboxes[mbox_id];

    if(mailbox->flagged_for_removal)
        return -1; // Mailbox is flagged for removal

    if(mailbox->slot_queue == NULL)
        blockMe(); // No messages ready to receive, so block

    // Search for a claimed slot, or the first unclaimed slot
    MailSlot* prev = NULL;
    MailSlot* slot = mailbox->slot_queue;
    while(slot != NULL)
    {
        // Deliverable slot found if claimed by current process or unclaimed by any
        // Break out of loop if so to actually deliver the message
        if(slot->claimed_by_pid == getpid() || !slot->claimed_by_pid)
            break;

        prev = slot;
        slot = slot->queue_next;
    }

    // If no deliverable slot found, add the current process to the consumer queue and block
    if(slot == NULL)
    {
        ShadowProcess* current = &shadow_table[getpid() % MAXPROC];
        if(mailbox->consumer_queue == NULL)
            mailbox->consumer_queue = current;
        else
        {
            ShadowProcess* last = mailbox->consumer_queue;
            while(last->consumer_queue_next != NULL)
                last = last->consumer_queue_next;
            last->consumer_queue_next = current;
        }

        blockMe();
    }

    // Remove slot from mailbox
    if(prev == NULL)
        mailbox->slot_queue = slot->queue_next;
    else
        prev->queue_next = slot->queue_next;

    // Message too large for buffer
    if(slot->message_size > msg_max_size)
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
    if(mailbox->producer_queue != NULL)
    {
        ShadowProcess* producer = mailbox->producer_queue;
        mailbox->producer_queue = producer->producer_queue_next;
        unblockProc(producer->pid);
    }

    return return_size;
}

// returns 0 if successful, 1 if mailbox full, -1 if illegal args
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size)
{
    check_kernel_mode(__func__ );
}

// returns 0 if successful, 1 if no msg available, -1 if illegal args
int MboxCondRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{
    check_kernel_mode(__func__ );
}

// type = interrupt device type, unit = # of device (when more than one),
// status = where interrupt handler puts device's status register.
void waitDevice(int type, int unit, int *status)
{
    check_kernel_mode(__func__ );
}

void wakeupByDevice(int type, int unit, int status)
{
    check_kernel_mode(__func__ );
}

void phase2_start_service_processes(void)
{

}