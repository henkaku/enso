/* first.c -- fixup environment and exec second payload
 *
 * Copyright (C) 2017 molecule
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <inttypes.h>
#include "nsbl.h"

// ALL OFFSETS ARE SPECIFIC TO 3.60

#define SECOND_PAYLOAD_OFFSET (5)
#define SECOND_PAYLOAD_SIZE (0x4000)

void go(void) {
    printf("first\n");
    // first payload reinits os0 device and reads second payload from emmc
    // this is because we only have 0x180 bytes for first payload

    memset((char*)0x511673A0, 0, 0x600); // clean after us

    // we need to patch call to read block 1 instead of block 0 as the master block
    // now that we store a copy of real partition table in block 1
    *(uint16_t*)0x510200C6 = 0x2101; // movs r1, #1

    clean_dcache((void *)0x510200C0, 0x20);
    flush_icache();

    // reinit os0_dev
    int (*fat_init_dev)() = (void*)0x5101FD19;
    char *os0_dev = (void*)0x51167784;
    int ret = fat_init_dev(os0_dev, 0x110000, 0x510010FD, 0x51028010); // os0_dev, flags, read_block, some_storage

    // TODO: what do these do? but we need them for some reason
    *(uint32_t*)(os0_dev + 0x2C) = 0;
    *(uint32_t*)(os0_dev + 0x78) = 0x1A000100;
    *(uint32_t*)(os0_dev + 0x84) = 0x1A001000;
    *(uint32_t*)(os0_dev + 0x90) = 0x0001002B;

    // restore corrupted boot args with our copy
    memcpy(boot_args, (*sysroot_ctx_ptr)->boot_args, sizeof(*boot_args));

    // allocate buffer for code
    SceKernelAllocMemBlockKernelOpt opt;
    int blk;
    void *base;
    void (*f)();
    memset(&opt, 0, sizeof(opt));
    opt.size = sizeof(opt);
    opt.attr = 0xA0400000;
    blk = sceKernelAllocMemBlock("", 0x1020D006, SECOND_PAYLOAD_SIZE, NULL);
    f = NULL;
    if (blk >= 0) {
        if (sceKernelGetMemBlockBase(blk, &base) >= 0) {
            // read code buffer
            if (read_block_os0(0x51028010, SECOND_PAYLOAD_OFFSET, SECOND_PAYLOAD_SIZE/512, base) >= 0) {
                // TODO: perhaps add some simple integrity check here?
                if (sceKernelRemapBlock(blk, 0x1020D005) >= 0) {
                    clean_dcache(base, SECOND_PAYLOAD_SIZE);
                    flush_icache();
                    f = (void*)(base + 1);
                }
            }
        }
    }

    // fallback: if for some reason we weren't able to allocate/read the payload, then don't run it
    if (f != NULL) {
        f();
    }

    // restore context and resume boot

    uint32_t *sp = *(uint32_t**)(0x51030100 + 0x220); // sp top for core 0
    uint32_t *old_sp = sp - 0x11d;

    // r0: 0x51167784 os0_dev
    // r1: 0xfffffffe
    // r2: sp - 0x110
    // r3: 0

    __asm__ volatile (
        "movw r0, #0x7784\n"
        "movt r0, #0x5116\n"
        "movw r1, #0xfffe\n"
        "movt r1, #0xffff\n"
        "mov r2, %0\n"
        "mov r3, #0\n"
        "mov sp, %1\n"
        "mov r4, %2\n"
        "bx r4\n" :: "r" (sp - 0x110), "r" (old_sp), "r" (0x5101F571) : "r0", "r1", "r2", "r3", "r4"
    );
}

__attribute__ ((section (".text.start"), naked)) void start(void)  {
    __asm__ volatile (
        "mov r0, #0\n"
        "movt r0, #0x51f0\n"
        "mov sp, r0\n"
        "b go\n"
    );
}
