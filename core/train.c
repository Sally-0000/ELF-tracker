#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dr_api.h"
#include "dr_ir_utils.h"
#include "dr_modules.h"
#include "drmgr.h"

typedef struct _enc_pair_entry_t {
    byte enc_site[16];
    byte enc_target[16];
    struct _enc_pair_entry_t *next;
} enc_pair_entry_t;

static enc_pair_entry_t *enc_pair_head = NULL;
static void *enc_pair_lock = NULL;

static char policy_file_path[512] = "./policy/default.policy";
static uint64 cscfi_hash_seed = 0x9e3779b97f4a7c15ULL;

static bool hex_to_bytes(const char *hex, byte *out, size_t out_len);
static void bytes_to_hex(const byte *in, size_t in_len, char *out);
static uint64 hash64(uint64 x);
static bool hash_offset_u64(uint64 offset, byte out_block[16]);
static bool insert_encrypted_pair_if_absent(const byte enc_site[16], const byte enc_target[16],
                                            bool *learned_new);
static void free_enc_pair_cache(void);
static void load_policy_file(void);
static void save_policy_file(void);
static void init_runtime_config(void);
static void event_exit(void);
static void at_indirect_call(app_pc instr_addr, app_pc target_addr);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
                                             instr_t *instr, bool for_trace,
                                             bool translating, void *user_data);

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

static void
bytes_to_hex(const byte *in, size_t in_len, char *out)
{
    size_t i;

    for (i = 0; i < in_len; ++i)
        snprintf(out + (i * 2), 3, "%02x", in[i]);
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
insert_encrypted_pair_if_absent(const byte enc_site[16], const byte enc_target[16],
                                bool *learned_new)
{
    enc_pair_entry_t *node;

    *learned_new = false;

    dr_mutex_lock(enc_pair_lock);
    for (node = enc_pair_head; node != NULL; node = node->next) {
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
    node->next = enc_pair_head;
    enc_pair_head = node;
    *learned_new = true;

    dr_mutex_unlock(enc_pair_lock);
    return true;
}

static void
free_enc_pair_cache(void)
{
    enc_pair_entry_t *node;
    enc_pair_entry_t *next;

    dr_mutex_lock(enc_pair_lock);
    node = enc_pair_head;
    enc_pair_head = NULL;
    dr_mutex_unlock(enc_pair_lock);

    while (node != NULL) {
        next = node->next;
        dr_global_free(node, sizeof(enc_pair_entry_t));
        node = next;
    }
}

static void
load_policy_file(void)
{
    FILE *fp;
    char line[256];
    byte enc_site[16];
    byte enc_target[16];
    bool learned_new;

    fp = fopen(policy_file_path, "r");
    if (fp == NULL)
        return;

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

        insert_encrypted_pair_if_absent(enc_site, enc_target, &learned_new);
    }

    fclose(fp);
}

static void
save_policy_file(void)
{
    FILE *fp;
    enc_pair_entry_t *node;
    char hex_site[33];
    char hex_target[33];

    fp = fopen(policy_file_path, "w");
    if (fp == NULL) {
        dr_printf("[train] failed to open policy file: %s\n", policy_file_path);
        return;
    }

    fprintf(fp, "# encrypted (site_offset,target_offset) pairs\n");

    dr_mutex_lock(enc_pair_lock);
    for (node = enc_pair_head; node != NULL; node = node->next) {
        bytes_to_hex(node->enc_site, 16, hex_site);
        bytes_to_hex(node->enc_target, 16, hex_target);
        hex_site[32] = '\0';
        hex_target[32] = '\0';
        fprintf(fp, "%s,%s\n", hex_site, hex_target);
    }
    dr_mutex_unlock(enc_pair_lock);

    fclose(fp);
}

static void
init_runtime_config(void)
{
    const char *file_env = getenv("ET_CSCFI_POLICY");
    const char *seed_env = getenv("ET_CSCFI_SEED");

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
}

static void
at_indirect_call(app_pc instr_addr, app_pc target_addr)
{
    module_data_t *src_mod;
    module_data_t *dst_mod;
    uint64 site_off;
    uint64 target_off;
    byte enc_site[16];
    byte enc_target[16];
    bool learned_new;

    src_mod = dr_lookup_module((byte *)instr_addr);
    dst_mod = dr_lookup_module((byte *)target_addr);
    if (src_mod == NULL || dst_mod == NULL) {
        if (src_mod != NULL)
            dr_free_module_data(src_mod);
        if (dst_mod != NULL)
            dr_free_module_data(dst_mod);
        return;
    }

    site_off = (uint64)(instr_addr - src_mod->start);
    target_off = (uint64)(target_addr - dst_mod->start);
    dr_free_module_data(src_mod);
    dr_free_module_data(dst_mod);

    if (!hash_offset_u64(site_off, enc_site) || !hash_offset_u64(target_off, enc_target))
        return;

    insert_encrypted_pair_if_absent(enc_site, enc_target, &learned_new);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    (void)drcontext;
    (void)tag;
    (void)for_trace;
    (void)translating;
    (void)user_data;

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    if (instr_is_call_indirect(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr,
                                      (app_pc)at_indirect_call, SPILL_SLOT_1);
    }

    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    drmgr_unregister_bb_insertion_event(event_app_instruction);
    drmgr_unregister_exit_event(event_exit);

    save_policy_file();
    free_enc_pair_cache();

    if (enc_pair_lock != NULL)
        dr_mutex_destroy(enc_pair_lock);

    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    (void)id;
    (void)argc;
    (void)argv;

    dr_set_client_name("ELF Tracker CSCFI Trainer", "https://dynamorio.org/");

    if (!drmgr_init()) {
        dr_printf("[train] drmgr_init failed\n");
        return;
    }

    enc_pair_lock = dr_mutex_create();
    if (enc_pair_lock == NULL) {
        dr_printf("[train] create lock failed\n");
        drmgr_exit();
        return;
    }

    init_runtime_config();
    load_policy_file();

    drmgr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
