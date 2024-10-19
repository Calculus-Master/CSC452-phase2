#include <phase1.h>
#include <phase2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Data Structures

typedef struct MailBox {

} MailBox;

typedef struct MailSlot {
    char message[MAX_MESSAGE];
} MailSlot;

typedef struct ShadowProcess {
    int pid;
} ShadowProcess;

static MailBox mailboxes[MAXMBOX];
static MailSlot mailslots[MAXSLOTS];
static ShadowProcess shadow_table[MAXPROC];

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

}

// returns 0 if successful, -1 if invalid arg
int MboxRelease(int mbox_id)
{

}

// returns 0 if successful, -1 if invalid args
int MboxSend(int mbox_id, void *msg_ptr, int msg_size)
{

}

// returns size of received msg if successful, -1 if invalid args
int MboxRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{

}

// returns 0 if successful, 1 if mailbox full, -1 if illegal args
int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size)
{

}

// returns 0 if successful, 1 if no msg available, -1 if illegal args
int MboxCondRecv(int mbox_id, void *msg_ptr, int msg_max_size)
{

}

// type = interrupt device type, unit = # of device (when more than one),
// status = where interrupt handler puts device's status register.
void waitDevice(int type, int unit, int *status)
{

}
void wakeupByDevice(int type, int unit, int status)
{

}