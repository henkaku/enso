/* nsbl.h -- imported data from non-secure bootloader
 *
 * Copyright (C) 2017 molecule
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef NSBL_HEADER
#define NSBL_HEADER

#include <inttypes.h>

#define NULL ((void *)0)

typedef struct SceModuleExports {
  uint16_t size;           // size of this structure; 0x20 for Vita 1.x
  uint8_t  lib_version[2]; //
  uint16_t attribute;      // ?
  uint16_t num_functions;  // number of exported functions
  uint16_t num_vars;       // number of exported variables
  uint16_t unk;
  uint32_t num_tls_vars;   // number of exported TLS variables?  <-- pretty sure wrong // yifanlu
  uint32_t lib_nid;        // NID of this specific export list; one PRX can export several names
  char     *lib_name;      // name of the export module
  uint32_t *nid_table;     // array of 32-bit NIDs for the exports, first functions then vars
  void     **entry_table;  // array of pointers to exported functions and then variables
} __attribute__((packed)) SceModuleExports;

#define EI_NIDENT 16
typedef struct Elf32_Ehdr {
  unsigned char e_ident[EI_NIDENT]; /* ident bytes */
  uint16_t  e_type;     /* file type */
  uint16_t  e_machine;    /* target machine */
  uint32_t  e_version;    /* file version */
  uint32_t  e_entry;    /* start address */
  uint32_t e_phoff;    /* phdr file offset */
  uint32_t e_shoff;    /* shdr file offset */
  uint32_t  e_flags;    /* file flags */
  uint16_t  e_ehsize;   /* sizeof ehdr */
  uint16_t  e_phentsize;    /* sizeof phdr */
  uint16_t  e_phnum;    /* number phdrs */
  uint16_t  e_shentsize;    /* sizeof shdr */
  uint16_t  e_shnum;    /* number shdrs */
  uint16_t  e_shstrndx;   /* shdr string index */
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
  uint32_t  p_type;   /* entry type */
  uint32_t p_offset; /* file offset */
  uint32_t  p_vaddr;  /* virtual address */
  uint32_t  p_paddr;  /* physical address */
  uint32_t  p_filesz; /* file size */
  uint32_t  p_memsz;  /* memory size */
  uint32_t  p_flags;  /* entry flags */
  uint32_t  p_align;  /* memory/file alignment */
} __attribute__((packed)) Elf32_Phdr;

typedef struct SceModuleSelfSectionInfo {
  uint64_t offset;
  uint64_t size;
  uint32_t compressed; // 2=compressed
  uint32_t unknown1;
  uint32_t encrypted; // 1=encrypted
  uint32_t unknown2;
} __attribute__((packed)) SceModuleSelfSectionInfo;

#ifdef FW_360

// firmware specific internal structures

typedef struct SceBootArgs {
  uint16_t version;
  uint16_t size;
  uint32_t fw_version;
  uint32_t ship_version;
  uint32_t field_C;
  uint32_t field_10;
  uint32_t field_14;
  uint32_t field_18;
  uint32_t field_1C;
  uint32_t field_20;
  uint32_t field_24;
  uint32_t field_28;
  uint8_t debug_flags[8];
  uint32_t field_34;
  uint32_t field_38;
  uint32_t field_3C;
  uint32_t field_40;
  uint32_t field_44;
  uint32_t field_48;
  uint32_t aslr_seed;
  uint32_t field_50;
  uint32_t field_54;
  uint32_t field_58;
  uint32_t field_5C;
  uint32_t dram_base;
  uint32_t dram_size;
  uint32_t field_68;
  uint32_t boot_type_indicator_1;
  uint8_t serial[0x10];
  uint32_t secure_kernel_enp_addr;
  uint32_t secure_kernel_enp_size;
  uint32_t field_88;
  uint32_t field_8C;
  uint32_t kprx_auth_sm_self_addr;
  uint32_t kprx_auth_sm_self_size;
  uint32_t prog_rvk_srvk_addr;
  uint32_t prog_rvk_srvk_size;
  uint16_t model;
  uint16_t device_type;
  uint16_t device_config;
  uint16_t retail_type;
  uint32_t field_A8;
  uint32_t field_AC;
  uint8_t session_id[0x10];
  uint32_t field_C0;
  uint32_t boot_type_indicator_2;
  uint32_t field_C8;
  uint32_t field_CC;
  uint32_t resume_context_addr;
  uint32_t field_D4;
  uint32_t field_D8;
  uint32_t field_DC;
  uint32_t field_E0;
  uint32_t field_E4;
  uint32_t field_E8;
  uint32_t field_EC;
  uint32_t field_F0;
  uint32_t field_F4;
  uint32_t bootldr_revision;
  uint32_t magic;
  uint8_t session_key[0x20];
  uint8_t unused[0xE0];
} __attribute__((packed)) SceBootArgs;

typedef struct SceSysrootContext {
  uint32_t reserved[27];
  SceBootArgs *boot_args;
} __attribute__((packed)) SceSysrootContext;

typedef struct SceModuleLoadList {
  const char *filename;
} __attribute__((packed)) SceModuleLoadList;

typedef struct SceObject {
  uint32_t field_0;
  void *obj_data;
  char data[];
} __attribute__((packed)) SceObject;

typedef struct SceModuleSegment {
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint16_t p_flags;
  uint16_t p_align_bits;
  void *buf;
  int32_t buf_blkid;
} __attribute__((packed)) SceModuleSegment;

typedef struct SceModuleObject {
  struct SceModuleObject *next;
  uint16_t exeflags;
  uint8_t status;
  uint8_t field_7;
  uint32_t min_sysver;
  int32_t modid;
  int32_t user_modid;
  int32_t pid;
  uint16_t modattribute;
  uint16_t modversion;
  uint32_t modid_name;
  SceModuleExports *ent_top_user;
  SceModuleExports *ent_end_user;
  uint32_t stub_start_user;
  uint32_t stub_end_user;
  uint32_t module_nid;
  uint32_t modinfo_field_38;
  uint32_t modinfo_field_3C;
  uint32_t modinfo_field_40;
  uint32_t exidx_start_user;
  uint32_t exidx_end_user;
  uint32_t extab_start_user;
  uint32_t extab_end_user;
  uint16_t num_export_libs;
  uint16_t num_import_libs;
  uint32_t field_54;
  uint32_t field_58;
  uint32_t field_5C;
  uint32_t field_60;
  void *imports;
  const char *path;
  uint32_t total_loadable;
  struct SceModuleSegment segments[3];
  void *type_6FFFFF00_buf;
  uint32_t type_6FFFFF00_bufsz;
  void *module_start;
  void *module_init;
  void *module_stop;
  uint32_t field_C0;
  uint32_t field_C4;
  uint32_t field_C8;
  uint32_t field_CC;
  uint32_t field_D0;
  struct SceObject *prev_loaded;
} __attribute__((packed)) SceModuleObject;

typedef struct SceKernelAllocMemBlockKernelOpt {
  uint32_t size;
  uint32_t field_4;
  uint32_t attr;
  uint32_t field_C;
  uint32_t paddr;
  uint32_t alignment;
  uint32_t field_18;
  uint32_t field_1C;
  uint32_t mirror_blkid;
  int32_t pid;
  uint32_t field_28;
  uint32_t field_2C;
  uint32_t field_30;
  uint32_t field_34;
  uint32_t field_38;
  uint32_t field_3C;
  uint32_t field_40;
  uint32_t field_44;
  uint32_t field_48;
  uint32_t field_4C;
  uint32_t field_50;
  uint32_t field_54;
} __attribute__((packed)) SceKernelAllocMemBlockKernelOpt;

typedef struct SceModuleDecryptContext {
  void *header;
  uint32_t header_len;
  Elf32_Ehdr *elf_ehdr;
  Elf32_Phdr *elf_phdr;
  uint8_t type;
  uint8_t init_completed;
  uint8_t field_12;
  uint8_t field_13;
  SceModuleSelfSectionInfo *section_info;
  void *header_buffer;
  uint32_t sbl_ctx;
  uint32_t field_20;
  uint32_t fd;
  int32_t pid;
  uint32_t max_size;
} __attribute__((packed)) SceModuleDecryptContext;

// firmware specific function offsets
#ifdef DEBUG
static int (*printf)(const char *fmt, ...) = (void*)0x510137A9;
#else
#define printf(...)
#endif
static void *(*memset)(void *dst, int ch, int sz) = (void*)0x51013AD1;
static void *(*memcpy)(void *dst, const void *src, int sz) = (void *)0x51013A51;
static void *(*memmove)(void *dst, const void *src, int sz) = (void *)0x51021325;
static void (*clean_dcache)(void *dst, int len) = (void*)0x5101456D;
static int (*read_block_os0)() = (void*)0x510010FD;
static void (*flush_icache)() = (void*)0x51014521;
static int (*strncmp)(const char *s1, const char *s2, int len) = (void *)0x51013B30;
static SceObject *(*get_obj_for_uid)(int uid) = (void *)0x51017649;
static int (*module_load)(const SceModuleLoadList *list, int *uids, int count, int) = (void *)0x51001551;
static int (*sceKernelAllocMemBlock)(const char *name, int type, int size, SceKernelAllocMemBlockKernelOpt *opt) = (void *)0x510086C1;
static int (*sceKernelGetMemBlockBase)(int32_t uid, void **basep) = (void *)0x510040E5;
static int (*sceKernelRemapBlock)(int32_t uid, int type) = (void *)0x510086D1;

// firmware specific patch offsets

static SceBootArgs *boot_args = (void *)0x51167528;
static SceSysrootContext **sysroot_ctx_ptr = (void *)0x51138A3C;
static void **module_load_func_ptr = (void *)0x51027630;

// sysstate patches
#define SCEDISPLAY_LOGO_OFFSET (0x8990)
#define SBLAUTHMGR_OFFSET_PATCH_ARG (168)
#define SYSSTATE_IS_MANUFACTURING_MODE_OFFSET (0x1500)
#define SYSSTATE_IS_DEV_MODE_OFFSET (0xE28)
#define SYSSTATE_RET_CHECK_BUG (0xD92)
static const uint8_t sysstate_ret_patch[] = {0x13, 0x22, 0xc8, 0xf2, 0x01, 0x02};
#define SYSSTATE_SD0_STRING (0x2460)
static const char ur0_path[] = "ur0:";
#define SYSSTATE_SD0_PSP2CONFIG_STRING (0x23AE)
static const char ur0_psp2config_path[] = "ur0:tai/boot_config.txt";
#define SYSSTATE_FINAL_CALL (0x130)
#define SYSSTATE_FINAL (0x18C9)

#else
#error "No firmware defined or firmware not supported."
#endif

#endif
