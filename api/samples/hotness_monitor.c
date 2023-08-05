/* ******************************************************************************
 * Copyright (c) 2015-2018 Google, Inc.  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * opcodes.c
 *
 * Reports the dynamic count of the total number of instructions executed
 * broken down by opcode.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include <stdlib.h> /* qsort */

#define ASSERT(x)                                            \
    do {                                                     \
        if (!(x)) {                                          \
            dr_printf("ASSERT failed on line %d", __LINE__); \
            dr_flush_file(STDOUT);                           \
            dr_abort();                                      \
        }                                                    \
    } while (0)

#ifdef WINDOWS
#    define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
#    define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif

#define NULL_TERMINATE(buf) (buf)[(sizeof((buf)) / sizeof((buf)[0])) - 1] = '\0'

#define HASH_TABLE_SIZE 7919
typedef struct cbr_counter_t {
    uint64 count;
} cbr_counter_t;

/* Each bucket in the hash table is a list of the following elements.
 * For each cbr, we store its address and its state.
 */
typedef struct _elem_t {
    struct _elem_t *next;
    cbr_counter_t counter;
    app_pc addr;
} elem_t;

typedef struct _list_t {
    elem_t *head;
    elem_t *tail;
} list_t;

/* We'll use one global hash table */
typedef list_t **hash_table_t;
hash_table_t global_table = NULL;

static elem_t *
new_elem(app_pc addr, cbr_counter_t counter)
{
    elem_t *elem = (elem_t *)dr_global_alloc(sizeof(elem_t));
    ASSERT(elem != NULL);

    elem->next = NULL;
    elem->addr = addr;
    elem->counter = counter;

    return elem;
}

static void
delete_elem(elem_t *elem)
{
    dr_global_free(elem, sizeof(elem_t));
}

static void
append_elem(list_t *list, elem_t *elem)
{
    if (list->head == NULL) {
        ASSERT(list->tail == NULL);
        list->head = elem;
        list->tail = elem;
    } else {
        list->tail->next = elem;
        list->tail = elem;
    }
}

static elem_t *
find_elem(list_t *list, app_pc addr)
{
    elem_t *elem = list->head;
    while (elem != NULL) {
        if (elem->addr == addr)
            return elem;
        elem = elem->next;
    }

    return NULL;
}

static list_t *
new_list()
{
    list_t *list = (list_t *)dr_global_alloc(sizeof(list_t));
    list->head = NULL;
    list->tail = NULL;
    return list;
}

static void
delete_list(list_t *list)
{
    elem_t *iter = list->head;
    while (iter != NULL) {
        elem_t *next = iter->next;
        delete_elem(iter);
        iter = next;
    }

    dr_global_free(list, sizeof(list_t));
}

hash_table_t
new_table()
{
    int i;
    hash_table_t table =
        (hash_table_t)dr_global_alloc(sizeof(list_t *) * HASH_TABLE_SIZE);

    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        table[i] = NULL;
    }

    return table;
}

void
delete_table(hash_table_t table)
{
    int i;
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        if (table[i] != NULL) {
            delete_list(table[i]);
        }
    }

    dr_global_free(table, sizeof(list_t *) * HASH_TABLE_SIZE);
}

static uint
hash_func(app_pc addr)
{
    return ((uint)(((ptr_uint_t)addr) % HASH_TABLE_SIZE));
}

elem_t *
lookup(hash_table_t table, app_pc addr)
{
    list_t *list = table[hash_func(addr)];
    if (list != NULL)
        return find_elem(list, addr);

    return NULL;
}

void
insert(hash_table_t table, app_pc addr, cbr_counter_t counter)
{
    elem_t *elem = new_elem(addr, counter);

    uint index = hash_func(addr);
    list_t *list = table[index];
    if (list == NULL) {
        list = new_list();
        table[index] = list;
    }

    append_elem(list, elem);
}


/* We keep a separate execution count per opcode.
 *
 * XXX: our counters are racy on ARM.  We use DRX_COUNTER_LOCK to make them atomic
 * (at a perf cost) on x86.
 *
 * XXX: we're using 32-bit counters.  64-bit counters are more challenging: they're
 * harder to make atomic on 32-bit x86, and drx does not yet support them on ARM.
 */
enum {
#ifdef X86
    ISA_X86_32,
    ISA_X86_64,
#elif defined(ARM)
    ISA_ARM_A32,
    ISA_ARM_THUMB,
#elif defined(AARCH64)
    ISA_ARM_A64,
#elif defined(RISCV64)
    ISA_RV64IMAFDC,
#endif
    NUM_ISA_MODE,
};
#define NUM_COUNT sizeof(count[0]) / sizeof(count[0][0])
/* We only display the top 15 counts.  This sample could be extended to
 * write all the counts to a file.
 *
 * XXX: DynamoRIO uses a separate stack for better transparency. DynamoRIO stack
 * has limited size, so we should keep NUM_COUNT_SHOW small to avoid the message
 * buffer (char msg[NUM_COUNT_SHOW*80]) in event_exit() overflowing the stack.
 * It won't work on Windows either if the output is too large.
 */
#define NUM_COUNT_SHOW 15

static void
event_exit(void);
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Sample Client 'opcodes'",
                       "http://dynamorio.org/issues");
    if (!drmgr_init())
        DR_ASSERT(false);
    drx_init();

    global_table = new_table();
    /* Register events: */
    dr_register_exit_event(event_exit);
    if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT(false);

    /* Make it easy to tell from the log file which client executed. */
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'opcodes' initializing\n");
#ifdef SHOW_RESULTS
    /* Also give notification to stderr. */
    if (dr_is_notify_on()) {
#    ifdef WINDOWS
        /* Ask for best-effort printing to cmd window.  Must be called at init. */
        dr_enable_console_printing();
#    endif
        dr_fprintf(STDERR, "Client opcodes is running\n");
    }
#endif
}


static void
event_exit(void)
{
#ifdef SHOW_RESULTS

    int i;
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        if (global_table[i] != NULL) {
            elem_t *iter;
            for (iter = global_table[i]->head; iter != NULL; iter = iter->next) {
                cbr_counter_t counter = iter->counter;
                dr_printf("" PFX ": %d\n", iter->addr, counter.count);
            }
        }
    }

#endif /* SHOW_RESULTS */
    if (!drmgr_unregister_bb_insertion_event(event_app_instruction))
        DR_ASSERT(false);
    drx_exit();
    delete_table(global_table);
    drmgr_exit();
}
/* This is called separately for each instruction in the block. */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    drmgr_disable_auto_predication(drcontext, bb);
    if (drmgr_is_first_instr(drcontext, instr)) {
      instr_t *ins;

        /* Normally looking ahead should be performed in the analysis event, but
         * here that would require storing the counts into an array passed in
         * user_data.  We avoid that overhead by cheating drmgr's model a little
         * bit and looking forward.  An alternative approach would be to insert
         * each counter before its respective instruction and have an
         * instru2instru pass that pulls the increments together to reduce
         * overhead.
         */
       for (ins = instrlist_first_app(bb); ins != NULL; ins = instr_get_next_app(ins)) {
            app_pc src = instr_get_app_pc(ins);
            elem_t* elem = lookup(global_table, src);

            if (elem == NULL) {
                cbr_counter_t counter;
                counter.count = 0;
                insert(global_table, src, counter);
                elem = lookup(global_table, src);
            }

            /* We insert all increments sequentially up front so that drx can
             * optimize the spills and restores.
             */
            drx_insert_counter_update(drcontext, bb, instr,
                                      /* We're using drmgr, so these slots
                                       * here won't be used: drreg's slots will be.
                                       */
                                      SPILL_SLOT_MAX + 1,
                                      IF_AARCHXX_(SPILL_SLOT_MAX + 1) &
                                        elem->counter.count,
                                      1,
                                      /* DRX_COUNTER_LOCK is not yet supported on ARM */
                                      IF_X86_ELSE(DRX_COUNTER_LOCK, 0));
       }
   }
    return DR_EMIT_DEFAULT;
}
