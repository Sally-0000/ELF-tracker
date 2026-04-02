#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "dr_ir_utils.h"
#include "dr_modules.h"
#include "dr_os_utils.h"

typedef struct {
	app_pc *entries;
	size_t size;
	size_t capacity;
	uint64 mismatch_count;
	uint64 resync_count;
	uint64 underflow_count;
	uint64 cfi_checked_count;
	uint64 cfi_violation_count;
	uint64 ibt_checked_count;
	uint64 ibt_violation_count;
	uint64 cscfi_checked_count;
	uint64 cscfi_violation_count;
	uint64 cscfi_learned_target_count;
} shadow_stack_t;

static int tls_idx = -1;

#define CSCFI_MAX_TARGETS_PER_SITE 8

typedef struct _callsite_policy_t {
	app_pc site;
	app_pc targets[CSCFI_MAX_TARGETS_PER_SITE];
	size_t target_count;
	struct _callsite_policy_t *next;
} callsite_policy_t;

typedef struct _module_ibt_policy_t {
	app_pc start;
	app_pc end;
	bool ibt_enabled;
	struct _module_ibt_policy_t *next;
} module_ibt_policy_t;

static module_ibt_policy_t *ibt_policy_head = NULL;
static void *ibt_policy_lock;
static callsite_policy_t *callsite_policy_head = NULL;
static void *callsite_policy_lock;
static app_pc main_module_start = NULL;
static app_pc main_module_end = NULL;

static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
											 instr_t *instr, bool for_trace,
											 bool translating, void *user_data);

static void at_call(app_pc return_addr);
static void at_ret(app_pc instr_addr, app_pc actual_return);
static void at_indirect_branch(app_pc instr_addr, app_pc target_addr);
static void at_indirect_call(app_pc instr_addr, app_pc target_addr);
static bool module_requires_ibt(app_pc target_addr);
static void free_ibt_policy_cache(void);
static void free_callsite_policy_cache(void);
static bool callsite_target_allowed(app_pc site, app_pc target, bool *learned_new);

static bool
in_main_module(app_pc pc)
{
	if (main_module_start == NULL || main_module_end == NULL)
		return false;
	return pc >= main_module_start && pc < main_module_end;
}

static bool
is_endbr_target(app_pc target_addr)
{
	byte op[4];
	size_t bytes_read = 0;

	if (!dr_safe_read(target_addr, sizeof(op), op, &bytes_read) || bytes_read != sizeof(op))
		return false;

	/* ENDBR64: F3 0F 1E FA, ENDBR32: F3 0F 1E FB */
	if (op[0] == 0xF3 && op[1] == 0x0F && op[2] == 0x1E && (op[3] == 0xFA || op[3] == 0xFB))
		return true;

	return false;
}

static bool
module_requires_ibt(app_pc target_addr)
{
	module_data_t *mod;
	module_ibt_policy_t *node;
	bool ibt_enabled = false;

	mod = dr_lookup_module((byte *)target_addr);
	if (mod == NULL)
		return false;

	dr_mutex_lock(ibt_policy_lock);
	for (node = ibt_policy_head; node != NULL; node = node->next) {
		if (target_addr >= node->start && target_addr < node->end) {
			ibt_enabled = node->ibt_enabled;
			dr_mutex_unlock(ibt_policy_lock);
			dr_free_module_data(mod);
			return ibt_enabled;
		}
	}
	dr_mutex_unlock(ibt_policy_lock);

	/* Heuristic: treat a module as IBT-enabled only if its entry point starts with ENDBR. */
	if (mod->entry_point != NULL)
		ibt_enabled = is_endbr_target(mod->entry_point);

	node = (module_ibt_policy_t *)dr_global_alloc(sizeof(module_ibt_policy_t));
	if (node != NULL) {
		node->start = mod->start;
		node->end = mod->end;
		node->ibt_enabled = ibt_enabled;
		dr_mutex_lock(ibt_policy_lock);
		node->next = ibt_policy_head;
		ibt_policy_head = node;
		dr_mutex_unlock(ibt_policy_lock);
	}

	dr_free_module_data(mod);
	return ibt_enabled;
}

static void
free_ibt_policy_cache(void)
{
	module_ibt_policy_t *node;
	module_ibt_policy_t *next;

	dr_mutex_lock(ibt_policy_lock);
	node = ibt_policy_head;
	ibt_policy_head = NULL;
	dr_mutex_unlock(ibt_policy_lock);

	while (node != NULL) {
		next = node->next;
		dr_global_free(node, sizeof(module_ibt_policy_t));
		node = next;
	}
}

static bool
callsite_target_allowed(app_pc site, app_pc target, bool *learned_new)
{
	callsite_policy_t *node;
	size_t i;

	*learned_new = false;

	dr_mutex_lock(callsite_policy_lock);
	for (node = callsite_policy_head; node != NULL; node = node->next) {
		if (node->site == site)
			break;
	}

	if (node == NULL) {
		node = (callsite_policy_t *)dr_global_alloc(sizeof(callsite_policy_t));
		if (node == NULL) {
			dr_mutex_unlock(callsite_policy_lock);
			return false;
		}
		memset(node, 0, sizeof(*node));
		node->site = site;
		node->next = callsite_policy_head;
		callsite_policy_head = node;
	}

	for (i = 0; i < node->target_count; ++i) {
		if (node->targets[i] == target) {
			dr_mutex_unlock(callsite_policy_lock);
			return true;
		}
	}

	if (node->target_count >= CSCFI_MAX_TARGETS_PER_SITE) {
		dr_mutex_unlock(callsite_policy_lock);
		return false;
	}

	node->targets[node->target_count++] = target;
	*learned_new = true;
	dr_mutex_unlock(callsite_policy_lock);
	return true;
}

static void
free_callsite_policy_cache(void)
{
	callsite_policy_t *node;
	callsite_policy_t *next;

	dr_mutex_lock(callsite_policy_lock);
	node = callsite_policy_head;
	callsite_policy_head = NULL;
	dr_mutex_unlock(callsite_policy_lock);

	while (node != NULL) {
		next = node->next;
		dr_global_free(node, sizeof(callsite_policy_t));
		node = next;
	}
}

static bool
is_valid_cfi_target(app_pc target_addr)
{
	dr_mem_info_t mem_info;
	module_data_t *mod;

	if (target_addr == NULL)
		return false;

	if (!dr_query_memory_ex((const byte *)target_addr, &mem_info))
		return false;

	if ((mem_info.prot & DR_MEMPROT_EXEC) == 0)
		return false;

	mod = dr_lookup_module((byte *)target_addr);
	if (mod == NULL)
		return false;

	dr_free_module_data(mod);
	return true;
}

static shadow_stack_t *
get_shadow_stack(void *drcontext)
{
	return (shadow_stack_t *)drmgr_get_tls_field(drcontext, tls_idx);
}

static bool
shadow_stack_grow(void *drcontext, shadow_stack_t *ss)
{
	size_t new_capacity;
	app_pc *new_entries;

	if (ss->capacity == 0)
		new_capacity = 256;
	else
		new_capacity = ss->capacity * 2;

	new_entries = (app_pc *)dr_thread_alloc(drcontext, new_capacity * sizeof(app_pc));
	if (new_entries == NULL)
		return false;

	if (ss->entries != NULL && ss->size > 0)
		memcpy(new_entries, ss->entries, ss->size * sizeof(app_pc));

	if (ss->entries != NULL)
		dr_thread_free(drcontext, ss->entries, ss->capacity * sizeof(app_pc));

	ss->entries = new_entries;
	ss->capacity = new_capacity;
	return true;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
	(void)id;
	(void)argc;
	(void)argv;

	dr_set_client_name("ELF Tracker Shadow Stack", "https://dynamorio.org/");

	if (!drmgr_init()) {
		dr_printf("[shadow-stack] drmgr_init failed\n");
		return;
	}

	ibt_policy_lock = dr_mutex_create();
	if (ibt_policy_lock == NULL) {
		dr_printf("[shadow-stack] create ibt lock failed\n");
		drmgr_exit();
		return;
	}

	callsite_policy_lock = dr_mutex_create();
	if (callsite_policy_lock == NULL) {
		dr_printf("[shadow-stack] create callsite lock failed\n");
		dr_mutex_destroy(ibt_policy_lock);
		drmgr_exit();
		return;
	}

	{
		module_data_t *main_mod = dr_get_main_module();
		if (main_mod != NULL) {
			main_module_start = main_mod->start;
			main_module_end = main_mod->end;
			dr_free_module_data(main_mod);
		}
	}

	tls_idx = drmgr_register_tls_field();
	if (tls_idx < 0) {
		dr_printf("[shadow-stack] register TLS field failed\n");
		drmgr_exit();
		return;
	}

	drmgr_register_exit_event(event_exit);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);
	drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}

static void
event_exit(void)
{
	drmgr_unregister_bb_insertion_event(event_app_instruction);
	drmgr_unregister_thread_init_event(event_thread_init);
	drmgr_unregister_thread_exit_event(event_thread_exit);
	drmgr_unregister_exit_event(event_exit);

	if (tls_idx >= 0)
		drmgr_unregister_tls_field(tls_idx);

	free_ibt_policy_cache();
	if (ibt_policy_lock != NULL)
		dr_mutex_destroy(ibt_policy_lock);
	free_callsite_policy_cache();
	if (callsite_policy_lock != NULL)
		dr_mutex_destroy(callsite_policy_lock);

	drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
	shadow_stack_t *ss = (shadow_stack_t *)dr_thread_alloc(drcontext, sizeof(shadow_stack_t));
	if (ss == NULL)
		return;

	memset(ss, 0, sizeof(*ss));
	if (!shadow_stack_grow(drcontext, ss)) {
		dr_thread_free(drcontext, ss, sizeof(*ss));
		return;
	}

	drmgr_set_tls_field(drcontext, tls_idx, ss);
}

static void
event_thread_exit(void *drcontext)
{
	shadow_stack_t *ss = get_shadow_stack(drcontext);

	if (ss == NULL)
		return;

	dr_printf(
			   "[shadow-stack] tid=%d mismatches=%llu resyncs=%llu underflows=%llu remaining=%llu cfi_checked=%llu cfi_violations=%llu ibt_checked=%llu ibt_violations=%llu cscfi_checked=%llu cscfi_violations=%llu cscfi_learned=%llu\n",
			   dr_get_thread_id(drcontext), (unsigned long long)ss->mismatch_count,
			   (unsigned long long)ss->resync_count,
			   (unsigned long long)ss->underflow_count, (unsigned long long)ss->size,
			   (unsigned long long)ss->cfi_checked_count,
			   (unsigned long long)ss->cfi_violation_count,
			   (unsigned long long)ss->ibt_checked_count,
			   (unsigned long long)ss->ibt_violation_count,
			   (unsigned long long)ss->cscfi_checked_count,
			   (unsigned long long)ss->cscfi_violation_count,
			   (unsigned long long)ss->cscfi_learned_target_count);

	if (ss->entries != NULL)
		dr_thread_free(drcontext, ss->entries, ss->capacity * sizeof(app_pc));
	dr_thread_free(drcontext, ss, sizeof(*ss));
}

static void
at_call(app_pc return_addr)
{
	void *drcontext = dr_get_current_drcontext();
	shadow_stack_t *ss = get_shadow_stack(drcontext);

	if (ss == NULL)
		return;

	if (ss->size == ss->capacity && !shadow_stack_grow(drcontext, ss))
		return;

	ss->entries[ss->size++] = return_addr;
}

static void
at_ret(app_pc instr_addr, app_pc actual_return)
{
	void *drcontext = dr_get_current_drcontext();
	shadow_stack_t *ss = get_shadow_stack(drcontext);
	app_pc expected_return = NULL;
	size_t i;

	(void)instr_addr;

	if (ss == NULL)
		return;

	if (ss->size == 0) {
		ss->underflow_count++;
		return;
	}

	expected_return = ss->entries[--ss->size];
	if (expected_return != actual_return) {
		for (i = ss->size; i > 0; --i) {
			if (ss->entries[i - 1] == actual_return) {
				ss->size = i - 1;
				ss->resync_count++;
				return;
			}
		}

		ss->mismatch_count++;
		dr_printf(
				   "[shadow-stack] mismatch tid=%d expected=%p actual=%p\n",
				   dr_get_thread_id(drcontext), expected_return, actual_return);
        dr_exit_process(1);
    }
}

static void
at_indirect_call(app_pc instr_addr, app_pc target_addr)
{
	void *drcontext = dr_get_current_drcontext();
	shadow_stack_t *ss = get_shadow_stack(drcontext);
	bool learned_new = false;

	if (ss == NULL)
		return;

	if (!in_main_module(instr_addr)) {
		at_indirect_branch(instr_addr, target_addr);
		return;
	}

	ss->cscfi_checked_count++;
	if (!callsite_target_allowed(instr_addr, target_addr, &learned_new)) {
		ss->cscfi_violation_count++;
		dr_printf("[cscfi] violation tid=%d site=%p target=%p\n", dr_get_thread_id(drcontext),
				  instr_addr, target_addr);
		dr_exit_process(1);
		return;
	}

	if (learned_new)
		ss->cscfi_learned_target_count++;

	at_indirect_branch(instr_addr, target_addr);
}

static void
at_indirect_branch(app_pc instr_addr, app_pc target_addr)
{
	void *drcontext = dr_get_current_drcontext();
	shadow_stack_t *ss = get_shadow_stack(drcontext);

	if (ss == NULL)
		return;

	ss->cfi_checked_count++;
	if (is_valid_cfi_target(target_addr))
	{
		if (!module_requires_ibt(target_addr))
			return;

		ss->ibt_checked_count++;
		if (is_endbr_target(target_addr))
			return;

		ss->ibt_violation_count++;
		dr_printf("[ibt] violation tid=%d branch=%p target=%p\n", dr_get_thread_id(drcontext),
				  instr_addr, target_addr);
		dr_exit_process(1);
		return;
	}

	ss->cfi_violation_count++;
	dr_printf("[cfi] violation tid=%d branch=%p target=%p\n", dr_get_thread_id(drcontext),
			  instr_addr, target_addr);
	dr_exit_process(1);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
					  bool for_trace, bool translating, void *user_data)
{
	app_pc instr_pc;
	app_pc return_addr;

	(void)tag;
	(void)for_trace;
	(void)translating;
	(void)user_data;

	if (!instr_is_app(instr))
		return DR_EMIT_DEFAULT;

	if (instr_is_call_direct(instr) || instr_is_call_indirect(instr)) {
		instr_pc = instr_get_app_pc(instr);
		if (instr_pc != NULL) {
			return_addr = instr_pc + instr_length(drcontext, instr);
			dr_insert_clean_call(drcontext, bb, instr, (void *)at_call, false, 1,
								 OPND_CREATE_INTPTR(return_addr));
		}

		if (instr_is_call_indirect(instr)) {
			dr_insert_mbr_instrumentation(drcontext, bb, instr,
							  (app_pc)at_indirect_call, SPILL_SLOT_2);
		}
	} else if (instr_is_return(instr)) {
		dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_ret, SPILL_SLOT_1);
	} else if (instr_is_mbr(instr)) {
		dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_indirect_branch,
						  SPILL_SLOT_2);
	}

	return DR_EMIT_DEFAULT;
}
