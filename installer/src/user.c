#include <psp2/kernel/modulemgr.h>

#include "enso.h"

// user library as a workaround to load kernel module at runtime

int ensoCheckOs0(void) {
	return k_ensoCheckOs0();
}

int ensoCheckMBR(void) {
	return k_ensoCheckMBR();
}

int ensoCheckBlocks(void) {
	return k_ensoCheckBlocks();
}

int ensoWriteConfig(void) {
	return k_ensoWriteConfig();
}

int ensoWriteBlocks(void) {
	return k_ensoWriteBlocks();
}

int ensoWriteMBR(void) {
	return k_ensoWriteMBR();
}

int ensoCheckRealMBR(void) {
	return k_ensoCheckRealMBR();
}

int ensoUninstallMBR(void) {
	return k_ensoUninstallMBR();
}

int ensoCleanUpBlocks(void) {
	return k_ensoCleanUpBlocks();
}

int module_start(int args, void *argv) {
	(void)args;
	(void)argv;
	return SCE_KERNEL_START_SUCCESS;
}
void _start() __attribute__ ((weak, alias ("module_start")));

int module_stop() {
	return SCE_KERNEL_STOP_SUCCESS;
}
