#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
    size_t module_cache_next;
    uint64 mismatch_count;
    uint64 resync_count;
    uint64 underflow_count;
    uint64 cfi_checked_count;
    uint64 cfi_violation_count;
    uint64 ibt_checked_count;
    uint64 ibt_violation_count;
    uint64 cscfi_checked_count;
    uint64 cscfi_violation_count;
    struct {
        app_pc start;
        app_pc end;
    } module_cache[8];
} shadow_stack_t;

static int tls_idx = -1;

#define CSCFI_DEFAULT_POLICY_PATH "./policy/default.policy"

typedef enum {
    CSCFI_ENFORCE_MAIN_ONLY = 0,
    CSCFI_ENFORCE_STRONG = 1,
} cscfi_enforce_mode_t;

typedef struct _enc_pair_entry_t {
    byte enc_site[16];
    byte enc_target[16];
    struct _enc_pair_entry_t *next;
} enc_pair_entry_t;

typedef struct {
    app_pc start;
    app_pc end;
} module_bounds_t;

typedef struct _module_ibt_policy_t {
    app_pc start;
    app_pc end;
    bool ibt_enabled;
    struct _module_ibt_policy_t *next;
} module_ibt_policy_t;

static module_ibt_policy_t *ibt_policy_head = NULL;
static void *ibt_policy_lock;
static enc_pair_entry_t *enc_pair_buckets[4096];
static void *enc_pair_lock;
static app_pc main_module_start = NULL;
static app_pc main_module_end = NULL;
static char policy_file_path[512] = CSCFI_DEFAULT_POLICY_PATH;
static cscfi_enforce_mode_t cscfi_enforce_mode = CSCFI_ENFORCE_MAIN_ONLY;
static uint64 cscfi_hash_seed = 0x9e3779b97f4a7c15ULL;

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
static void check_indirect_edge(app_pc instr_addr, app_pc target_addr);
static bool module_requires_ibt(app_pc target_addr);
static void free_ibt_policy_cache(void);
static void free_enc_pair_cache(void);
static bool has_encrypted_pair(const byte enc_site[16], const byte enc_target[16]);
static bool insert_encrypted_pair_if_absent(const byte enc_site[16], const byte enc_target[16]);
static size_t enc_pair_bucket_index(const byte enc_site[16], const byte enc_target[16]);
static bool lookup_module_bounds_cached(shadow_stack_t *ss, app_pc pc, module_bounds_t *out);
static bool hex_to_bytes(const char *hex, byte *out, size_t out_len);
static uint64 hash64(uint64 x);
static bool hash_offset_u64(uint64 offset, byte out_block[16]);
static void cscfi_init_runtime_config(void);
static void cscfi_load_policy_file(void);

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
hex_to_bytes(const char *hex, byte *out, size_t out_len)
{
    size_t i;

    for (i = 0; i < out_len; ++i) {
        unsigned int v;
        if (sscanf(hex + (i * 2), "%2x", &v) != 1)
            return false;
        out[i] = (byte)v;
    }
    return true;
}

static uint64
hash64(uint64 x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static bool
hash_offset_u64(uint64 offset, byte out_block[16])
{
    uint64 h1;
    uint64 h2;

    h1 = hash64(offset ^ cscfi_hash_seed);
    h2 = hash64(h1 ^ 0xa0761d6478bd642fULL);
    memcpy(out_block, &h1, sizeof(h1));
    memcpy(out_block + sizeof(h1), &h2, sizeof(h2));
    return true;
}

static bool
lookup_module_bounds_cached(shadow_stack_t *ss, app_pc pc, module_bounds_t *out)
{
    size_t i;
    module_data_t *mod;

    for (i = 0; i < sizeof(ss->module_cache) / sizeof(ss->module_cache[0]); ++i) {
        if (pc >= ss->module_cache[i].start && pc < ss->module_cache[i].end) {
            out->start = ss->module_cache[i].start;
            out->end = ss->module_cache[i].end;
            return true;
        }
    }

    mod = dr_lookup_module((byte *)pc);
    if (mod == NULL)
        return false;

    out->start = mod->start;
    out->end = mod->end;
    ss->module_cache[ss->module_cache_next].start = mod->start;
    ss->module_cache[ss->module_cache_next].end = mod->end;
    ss->module_cache_next =
        (ss->module_cache_next + 1) % (sizeof(ss->module_cache) / sizeof(ss->module_cache[0]));

    dr_free_module_data(mod);
    return true;
}

static size_t
enc_pair_bucket_index(const byte enc_site[16], const byte enc_target[16])
{
    uint64 site_lo;
    uint64 target_lo;

    memcpy(&site_lo, enc_site, sizeof(site_lo));
    memcpy(&target_lo, enc_target, sizeof(target_lo));
    return (size_t)((site_lo ^ target_lo) & (4096 - 1));
}

static bool
insert_encrypted_pair_if_absent(const byte enc_site[16], const byte enc_target[16])
{
    enc_pair_entry_t *node;
    size_t bucket;

    bucket = enc_pair_bucket_index(enc_site, enc_target);

    dr_mutex_lock(enc_pair_lock);
    for (node = enc_pair_buckets[bucket]; node != NULL; node = node->next) {
        if (memcmp(node->enc_site, enc_site, 16) == 0 &&
            memcmp(node->enc_target, enc_target, 16) == 0) {
            dr_mutex_unlock(enc_pair_lock);
            return true;
        }
    }

    node = (enc_pair_entry_t *)dr_global_alloc(sizeof(enc_pair_entry_t));
    if (node == NULL) {
        dr_mutex_unlock(enc_pair_lock);
        return false;
    }

    memcpy(node->enc_site, enc_site, 16);
    memcpy(node->enc_target, enc_target, 16);
    node->next = enc_pair_buckets[bucket];
    enc_pair_buckets[bucket] = node;
    dr_mutex_unlock(enc_pair_lock);
    return true;
}

static void
free_enc_pair_cache(void)
{
    enc_pair_entry_t *node;
    enc_pair_entry_t *next;
    enc_pair_entry_t *buckets[4096];
    size_t i;

    dr_mutex_lock(enc_pair_lock);
    for (i = 0; i < sizeof(enc_pair_buckets) / sizeof(enc_pair_buckets[0]); ++i) {
        buckets[i] = enc_pair_buckets[i];
        enc_pair_buckets[i] = NULL;
    }
    dr_mutex_unlock(enc_pair_lock);

    for (i = 0; i < sizeof(buckets) / sizeof(buckets[0]); ++i) {
        node = buckets[i];
        while (node != NULL) {
            next = node->next;
            dr_global_free(node, sizeof(enc_pair_entry_t));
            node = next;
        }
    }
}

static bool
has_encrypted_pair(const byte enc_site[16], const byte enc_target[16])
{
    enc_pair_entry_t *node;
    size_t bucket;

    bucket = enc_pair_bucket_index(enc_site, enc_target);

    dr_mutex_lock(enc_pair_lock);
    for (node = enc_pair_buckets[bucket]; node != NULL; node = node->next) {
        if (memcmp(node->enc_site, enc_site, 16) == 0 &&
            memcmp(node->enc_target, enc_target, 16) == 0) {
            dr_mutex_unlock(enc_pair_lock);
            return true;
        }
    }
    dr_mutex_unlock(enc_pair_lock);
    return false;
}

static void
cscfi_init_runtime_config(void)
{
    const char *file_env = getenv("ET_CSCFI_POLICY");
    const char *seed_env = getenv("ET_CSCFI_SEED");
    const char *mode_env = getenv("ET_CSCFI_ENFORCE_MODE");

    if (file_env != NULL && file_env[0] != '\0') {
        size_t n = strlen(file_env);
        if (n >= sizeof(policy_file_path))
            n = sizeof(policy_file_path) - 1;
        memcpy(policy_file_path, file_env, n);
        policy_file_path[n] = '\0';
    }

    if (seed_env != NULL && seed_env[0] != '\0') {
        char *endptr = NULL;
        unsigned long long v = strtoull(seed_env, &endptr, 0);
        if (endptr != seed_env)
            cscfi_hash_seed = (uint64)v;
    }

    if (mode_env != NULL && strcmp(mode_env, "strong") == 0)
        cscfi_enforce_mode = CSCFI_ENFORCE_STRONG;
    else
        cscfi_enforce_mode = CSCFI_ENFORCE_MAIN_ONLY;
}

static void
cscfi_load_policy_file(void)
{
    FILE *fp;
    char line[256];
    byte enc_site[16];
    byte enc_target[16];

    fp = fopen(policy_file_path, "r");
    if (fp == NULL) {
        dr_printf("[cscfi] policy file not found: %s\n", policy_file_path);
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *nl = strchr(line, '\n');
        char *comma;

        if (nl != NULL)
            *nl = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;

        comma = strchr(line, ',');
        if (comma == NULL)
            continue;
        *comma = '\0';

        if (!hex_to_bytes(line, enc_site, sizeof(enc_site)) ||
            !hex_to_bytes(comma + 1, enc_target, sizeof(enc_target)))
            continue;

        insert_encrypted_pair_if_absent(enc_site, enc_target);
    }

    fclose(fp);
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

    enc_pair_lock = dr_mutex_create();
    if (enc_pair_lock == NULL) {
        dr_printf("[shadow-stack] create callsite lock failed\n");
        dr_mutex_destroy(ibt_policy_lock);
        drmgr_exit();
        return;
    }

    cscfi_init_runtime_config();
    cscfi_load_policy_file();
    if (cscfi_enforce_mode == CSCFI_ENFORCE_STRONG)
        dr_printf("[cscfi] enforce mode: strong\n");
    else
        dr_printf("[cscfi] enforce mode: main-only\n");

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
    free_enc_pair_cache();
    if (enc_pair_lock != NULL)
        dr_mutex_destroy(enc_pair_lock);

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

    dr_printf("[shadow-stack] tid=%d mismatches=%llu resyncs=%llu underflows=%llu remaining=%llu cfi_checked=%llu cfi_violations=%llu ibt_checked=%llu ibt_violations=%llu cscfi_checked=%llu cscfi_violations=%llu\n",
              dr_get_thread_id(drcontext),
              (unsigned long long)ss->mismatch_count,
              (unsigned long long)ss->resync_count,
              (unsigned long long)ss->underflow_count,
              (unsigned long long)ss->size,
              (unsigned long long)ss->cfi_checked_count,
              (unsigned long long)ss->cfi_violation_count,
              (unsigned long long)ss->ibt_checked_count,
              (unsigned long long)ss->ibt_violation_count,
              (unsigned long long)ss->cscfi_checked_count,
              (unsigned long long)ss->cscfi_violation_count);

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
        dr_printf("[shadow-stack] mismatch tid=%d expected=%p actual=%p\n",
                  dr_get_thread_id(drcontext), expected_return, actual_return);
        dr_exit_process(1);
    }
}

static void
check_indirect_edge(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    shadow_stack_t *ss = get_shadow_stack(drcontext);
    module_bounds_t src_mod;
    module_bounds_t dst_mod;
    byte enc_site[16];
    byte enc_target[16];
    uint64 site_off;
    uint64 target_off;

    if (ss == NULL)
        return;

    if (cscfi_enforce_mode == CSCFI_ENFORCE_MAIN_ONLY && !in_main_module(instr_addr)) {
        at_indirect_branch(instr_addr, target_addr);
        return;
    }

    ss->cscfi_checked_count++;

    if (!lookup_module_bounds_cached(ss, instr_addr, &src_mod) ||
        !lookup_module_bounds_cached(ss, target_addr, &dst_mod)) {
        ss->cscfi_violation_count++;
        dr_printf("[cscfi] mismatch tid=%d site=%p target=%p (no module)\n",
                  dr_get_thread_id(drcontext), instr_addr, target_addr);
        dr_exit_process(1);
        return;
    }

    site_off = (uint64)(instr_addr - src_mod.start);
    target_off = (uint64)(target_addr - dst_mod.start);

    if (!hash_offset_u64(site_off, enc_site) ||
        !hash_offset_u64(target_off, enc_target) ||
        !has_encrypted_pair(enc_site, enc_target)) {
        ss->cscfi_violation_count++;
        dr_printf("[cscfi] mismatch tid=%d site=%p target=%p\n",
                  dr_get_thread_id(drcontext), instr_addr, target_addr);
        dr_exit_process(1);
        return;
    }

    at_indirect_branch(instr_addr, target_addr);
}

static void
at_indirect_call(app_pc instr_addr, app_pc target_addr)
{
    check_indirect_edge(instr_addr, target_addr);
}

static void
at_indirect_branch(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    shadow_stack_t *ss = get_shadow_stack(drcontext);

    if (ss == NULL)
        return;

    ss->cfi_checked_count++;
    if (is_valid_cfi_target(target_addr)) {
        if (!module_requires_ibt(target_addr))
            return;

        ss->ibt_checked_count++;
        if (is_endbr_target(target_addr))
            return;

        ss->ibt_violation_count++;
        dr_printf("[ibt] violation tid=%d branch=%p target=%p\n",
                  dr_get_thread_id(drcontext), instr_addr, target_addr);
        dr_exit_process(1);
        return;
    }

    ss->cfi_violation_count++;
    dr_printf("[cfi] violation tid=%d branch=%p target=%p\n",
              dr_get_thread_id(drcontext), instr_addr, target_addr);
    dr_exit_process(1);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    (void)tag;
    (void)for_trace;
    (void)translating;
    (void)user_data;

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    if (instr_is_call_direct(instr) || instr_is_call_indirect(instr)) {
        app_pc instr_pc = instr_get_app_pc(instr);
        app_pc return_addr;

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
    } else if (instr_is_mbr(instr) && !instr_is_return(instr) && !instr_is_call(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr,
                                      (app_pc)check_indirect_edge, SPILL_SLOT_2);
    }

    return DR_EMIT_DEFAULT;
}
