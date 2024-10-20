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
    char message[MAX_MESSAGE];
    struct MailSlot* queue_next;
} MailSlot;

typedef struct MailBox {
    short in_use;
    short flagged_for_removal;

    int num_slots;
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

// Phase 2 Functions

void phase2_init(void)
{
    // Clear out all mailboxes, slots, and shadow process table
    memset(mailboxes, 0, sizeof(mailboxes));
    memset(mailslots, 0, sizeof(mailslots));
    memset(shadow_table, 0, sizeof(shadow_table));
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
    mbox->num_slots = slots;
    mbox->slot_size = slot_size;

    return next_mbox_id - 1;
}

// returns 0 if successful, -1 if invalid arg
int MboxRelease(int mbox_id)
{
    check_kernel_mode(__func__ );

    // Check if mbox_id is valid
    int valid = 0;
    for(int i = 0; i < MAXMBOX; i++)
        if(mailboxes[i].in_use)
            valid = 1;

    if(!valid) return -1;

    MailBox* mailbox = &mailboxes[mbox_id];

    // Flag for removal in case a Context Switch occurs
    mailbox->flagged_for_removal = 1;

    // Release slots
    MailSlot* slot = mailbox->slot_queue;
    while(slot != NULL)
    {
        MailSlot* next = slot->queue_next;
        memset(slot, 0, sizeof(MailSlot));
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
}

// returns size of received msg if successful, -1 if invalid args
int MboxRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{
    check_kernel_mode(__func__ );
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