#pragma once

// user prototypes
int ensoCheckOs0(void);
int ensoCheckMBR(void);
int ensoCheckBlocks(void);
int ensoWriteConfig(void);
int ensoWriteBlocks(void);
int ensoWriteMBR(void);
int ensoCheckRealMBR(void);
int ensoUninstallMBR(void);
int ensoCleanUpBlocks(void);

// kernel prototypes
int k_ensoCheckOs0(void);
int k_ensoCheckMBR(void);
int k_ensoCheckBlocks(void);
int k_ensoWriteConfig(void);
int k_ensoWriteBlocks(void);
int k_ensoWriteMBR(void);
int k_ensoCheckRealMBR(void);
int k_ensoUninstallMBR(void);
int k_ensoCleanUpBlocks(void);

enum {
	E_PREVIOUS_INSTALL = 1,
	E_MBR_BUT_UNKNOWN = 2,
	E_UNKNOWN_DATA = 3,
};

#define BLOCKS_OUTPUT "ux0:data/blocks.bin"
