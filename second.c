/* second.c -- bootloader patches
 *
 * Copyright (C) 2017 molecule
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <inttypes.h>
#include "nsbl.h"
#include "logo.h"

#define unlikely(expr) __builtin_expect(!!(expr), 0)

#define DACR_OFF(stmt)                 \
do {                                   \
    unsigned prev_dacr;                \
    __asm__ volatile(                  \
        "mrc p15, 0, %0, c3, c0, 0 \n" \
        : "=r" (prev_dacr)             \
    );                                 \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (0xFFFF0000)           \
    );                                 \
    stmt;                              \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (prev_dacr)            \
    );                                 \
} while (0)

#define INSTALL_HOOK_THUMB(func, addr) \
do {                                                \
    unsigned *target;                                 \
    target = (unsigned*)(addr);                       \
    *target++ = 0xC004F8DF; /* ldr.w    ip, [pc, #4] */ \
    *target++ = 0xBF004760; /* bx ip; nop */          \
    *target = (unsigned)func;                         \
} while (0)

#define INSTALL_RET_THUMB(addr, ret)   \
do {                                   \
    unsigned *target;                  \
    target = (unsigned*)(addr);        \
    *target = 0x47702000 | (ret); /* movs r0, #ret; bx lr */ \
} while (0)

// sdstor restore globals
static int (*sdstor_read_sector_async)(void* ctx, int sector, char* buffer, int nSectors) = NULL;
static int (*sdstor_read_sector)(void* ctx, int sector, char* buffer, int nSectors) = NULL;
static void *(*get_sd_context_part_validate_mmc)(int sd_ctx_index) = NULL;

// debug globals
#ifdef DEBUG
static int (*set_crash_flag)(int) = NULL;
#endif

// sigpatch globals
static int g_sigpatch_disabled = 0;
static int g_homebrew_decrypt = 0;
static int (*sbl_parse_header)(uint32_t ctx, const void *header, int len, void *args) = NULL;
static int (*sbl_set_up_buffer)(uint32_t ctx, int segidx) = NULL;
static int (*sbl_decrypt)(uint32_t ctx, void *buf, int sz) = NULL;

// sysstate final function
static void __attribute__((noreturn)) (*sysstate_final)(void) = NULL;

// utility functions

#if 0
static int hex_dump(const char *addr, unsigned int size)
{
    unsigned int i;
    for (i = 0; i < (size >> 4); i++)
    {
        printf("0x%08X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", addr, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
        addr += 0x10;
    }
    return 0;
}
#endif

static void **get_export_func(SceModuleObject *mod, uint32_t lib_nid, uint32_t func_nid) {
    for (SceModuleExports *ent = mod->ent_top_user; ent != mod->ent_end_user; ent++) {
        if (ent->lib_nid == lib_nid) {
            for (int i = 0; i < ent->num_functions; i++) {
                if (ent->nid_table[i] == func_nid) {
                    return &ent->entry_table[i];
                }
            }
        }
    }
    return NULL;
}

static int is_safe_mode(void) {
    SceBootArgs *boot_args = (*sysroot_ctx_ptr)->boot_args;
    uint32_t v;

    if (boot_args->debug_flags[7] != 0xFF) {
        return 1;
    }

    v = boot_args->boot_type_indicator_2 & 0x7F;
    if (v == 0xB || (v == 4 && boot_args->resume_context_addr)) {
        v = ~boot_args->field_CC;
        if (((v >> 8) & 0x54) == 0x54 && (v & 0xC0) == 0) {
            return 1;
        } else {
            return 0;
        }
    } else if (v == 4) {
        return 0;
    }

    if (v == 0x1F || (uint32_t)(v - 0x18) <= 1) {
        return 1;
    } else {
        return 0;
    }
}

static int is_update_mode(void) {
    SceBootArgs *boot_args = (*sysroot_ctx_ptr)->boot_args;

    if (boot_args->debug_flags[4] != 0xFF) {
        return 1;
    } else {
        return 0;
    }
}

static inline int skip_patches(void) {
    return is_safe_mode() || is_update_mode();
}

// sdif patches for MBR redirection

static int sdstor_read_sector_patched(void* ctx, int sector, char* buffer, int nSectors) {
    int ret;
#ifndef NO_MBR_REDIRECT
    if (unlikely(sector == 0 && nSectors > 0)) {
        printf("read sector 0 for %d at context 0x%08X\n", nSectors, ctx);
        if (get_sd_context_part_validate_mmc(0) == ctx) {
            printf("patching sector 0 read to sector 1\n");
            ret = sdstor_read_sector(ctx, 1, buffer, 1);
            if (ret >= 0 && nSectors > 1) {
                ret = sdstor_read_sector(ctx, 1, buffer + 0x200, nSectors-1);
            }
            return ret;
        }
    }
#endif

    return sdstor_read_sector(ctx, sector, buffer, nSectors);
}

static int sdstor_read_sector_async_patched(void* ctx, int sector, char* buffer, int nSectors) {
    int ret;
#ifndef NO_MBR_REDIRECT
    if (unlikely(sector == 0 && nSectors > 0)) {
        printf("read sector async 0 for %d at context 0x%08X\n", nSectors, ctx);
        if (get_sd_context_part_validate_mmc(0) == ctx) {
            printf("patching sector 0 read to sector 1\n");
            ret = sdstor_read_sector_async(ctx, 1, buffer, 1);
            if (ret >= 0 && nSectors > 1) {
                ret = sdstor_read_sector_async(ctx, 1, buffer + 0x200, nSectors-1);
            }
            return ret;
        }
    }
#endif

    return sdstor_read_sector_async(ctx, sector, buffer, nSectors);
}

// sigpatches for bootup

static int sbl_parse_header_patched(uint32_t ctx, const void *header, int len, void *args) {
    int ret = sbl_parse_header(ctx, header, len, args);
    if (unlikely(!g_sigpatch_disabled)) {
        DACR_OFF(
            g_homebrew_decrypt = (ret < 0);
        );
        if (g_homebrew_decrypt) {
            *(uint32_t *)(args + SBLAUTHMGR_OFFSET_PATCH_ARG) = 0x40;
            ret = 0;
        }
    }
    return ret;
}

static int sbl_set_up_buffer_patched(uint32_t ctx, int segidx) {
    if (unlikely(!g_sigpatch_disabled)) {
        if (g_homebrew_decrypt) {
            return 2; // always compressed!
        }
    }
    return sbl_set_up_buffer(ctx, segidx);
}

static int sbl_decrypt_patched(uint32_t ctx, void *buf, int sz) {
    if (unlikely(!g_sigpatch_disabled)) {
        if (g_homebrew_decrypt) {
            return 0;
        }
    }
    return sbl_decrypt(ctx, buf, sz);
}

static void __attribute__((noreturn)) sysstate_final_hook(void) {
    printf("after kernel load! disabling temporary sigpatches\n");

    DACR_OFF(
        g_sigpatch_disabled = 1;
    );

    sysstate_final();
}

// main function to hook stuff

#define HOOK_EXPORT(name, lib_nid, func_nid) do {           \
    void **func = get_export_func(mod, lib_nid, func_nid);  \
    printf(#name ": 0x%08X\n", *func);                      \
    DACR_OFF(                                               \
        name = *func;                                       \
        *func = name ## _patched;                           \
    );                                                      \
} while (0)
#define FIND_EXPORT(name, lib_nid, func_nid) do {           \
    void **func = get_export_func(mod, lib_nid, func_nid);  \
    printf(#name ": 0x%08X\n", *func);                      \
    DACR_OFF(                                               \
        name = *func;                                       \
    );                                                      \
} while (0)
static int module_load_patched(const SceModuleLoadList *list, int *uids, int count, int unk) {
    int ret;
    SceObject *obj;
    SceModuleObject *mod;
    int skip;
    int sysmem_idx = -1, display_idx = -1, sdif_idx = -1, authmgr_idx = -1, sysstate_idx = -1;

    skip = skip_patches();
    for (int i = 0; i < count; i++) {
        if (!list[i].filename) {
            continue; // wtf sony why don't you sanitize input
        }
        printf("before start %s\n", list[i].filename);
        if (!skip && strncmp(list[i].filename, "display.skprx", 13) == 0) {
            display_idx = i;
        } else if (strncmp(list[i].filename, "sdif.skprx", 10) == 0) {
            sdif_idx = i; // never skip MBR redirection patches
        } else if (!skip && strncmp(list[i].filename, "authmgr.skprx", 13) == 0) {
            authmgr_idx = i;
        } else if (!skip && strncmp(list[i].filename, "sysstatemgr.skprx", 17) == 0) {
            sysstate_idx = i;
        }
#ifdef DEBUG
        if (strncmp(list[i].filename, "sysmem.skprx", 12) == 0) {
            sysmem_idx = i;
        }
#endif
    }
    ret = module_load(list, uids, count, unk);
#ifdef DEBUG
    // get sysmem functions
    if (sysmem_idx >= 0) {
        obj = get_obj_for_uid(uids[sysmem_idx]);
        if (obj != NULL) {
            mod = (SceModuleObject *)&obj->data;
            FIND_EXPORT(set_crash_flag, 0x13D793B7, 0xA465A31A);
            FIND_EXPORT(printf, 0x88758561, 0x391B74B7);
        } else {
            printf("module data invalid for sysmem.skprx!\n");
        }
    }
#endif
    // patch logo
    if (display_idx >= 0) {
        obj = get_obj_for_uid(uids[display_idx]);
        if (obj != NULL) {
            mod = (SceModuleObject *)&obj->data;
            printf("logo at offset: %x\n", mod->segments[0].buf + SCEDISPLAY_LOGO_OFFSET);
            DACR_OFF(
                memcpy(mod->segments[0].buf + SCEDISPLAY_LOGO_OFFSET, logo_data, logo_len);
            );
            // no cache flush needed because this is just data
        } else {
            printf("module data invalid for display.skprx!\n");
        }
    }
    // patch sdif
    if (sdif_idx >= 0) {
        obj = get_obj_for_uid(uids[sdif_idx]);
        if (obj != NULL) {
            mod = (SceModuleObject *)&obj->data;
            HOOK_EXPORT(sdstor_read_sector_async, 0x96D306FA, 0x6F8D529B);
            HOOK_EXPORT(sdstor_read_sector, 0x96D306FA, 0xB9593652);
            FIND_EXPORT(get_sd_context_part_validate_mmc, 0x96D306FA, 0x6A71987F);
        } else {
            printf("module data invalid for sdif.skprx!\n");
        }
    }
    // patch authmgr
    if (authmgr_idx >= 0) {
        obj = get_obj_for_uid(uids[authmgr_idx]);
        if (obj != NULL) {
            mod = (SceModuleObject *)&obj->data;
            HOOK_EXPORT(sbl_parse_header, 0x7ABF5135, 0xF3411881);
            HOOK_EXPORT(sbl_set_up_buffer, 0x7ABF5135, 0x89CCDA2C);
            HOOK_EXPORT(sbl_decrypt, 0x7ABF5135, 0xBC422443);
        } else {
            printf("module data invalid for authmgr.skprx!\n");
        }
    }
    // patch sysstate to load unsigned boot configs
    if (sysstate_idx >= 0) {
        obj = get_obj_for_uid(uids[sysstate_idx]);
        if (obj != NULL) {
            mod = (SceModuleObject *)&obj->data;
            DACR_OFF(
                INSTALL_RET_THUMB(mod->segments[0].buf + SYSSTATE_IS_MANUFACTURING_MODE_OFFSET, 1);
                *(uint32_t *)(mod->segments[0].buf + SYSSTATE_IS_DEV_MODE_OFFSET) = 0x20012001;
                memcpy(mod->segments[0].buf + SYSSTATE_RET_CHECK_BUG, sysstate_ret_patch, sizeof(sysstate_ret_patch));
                memcpy(mod->segments[0].buf + SYSSTATE_SD0_STRING, ur0_path, sizeof(ur0_path));
                memcpy(mod->segments[0].buf + SYSSTATE_SD0_PSP2CONFIG_STRING, ur0_psp2config_path, sizeof(ur0_psp2config_path));
                // this patch actually corrupts two words of data, but they are only used in debug printing and seem to be fine
                INSTALL_HOOK_THUMB(sysstate_final_hook, mod->segments[0].buf + SYSSTATE_FINAL_CALL);
                sysstate_final = mod->segments[0].buf + SYSSTATE_FINAL;
            );
        } else {
            printf("module data invalid for sysstatemgr.skprx!\n");
        }
    }
    return ret;
}
#undef HOOK_EXPORT
#undef FIND_EXPORT

void go(void) {
    printf("second\n");

    // patch module_load/module_start
    *module_load_func_ptr = module_load_patched;
    printf("module_load_patched: 0x%08X\n", module_load_patched);
}

__attribute__ ((section (".text.start"))) void start(void) {
    go();
}
