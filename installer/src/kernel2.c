#include <psp2kern/kernel/modulemgr.h>

#include <taihen.h>

static tai_hook_ref_t unload_allowed_hook;
static SceUID unload_allowed_uid;

int unload_allowed_patched(void) {
	TAI_CONTINUE(int, unload_allowed_hook);
	return 1; // always allowed
}

int module_start(int args, void *argv) {
	(void)args;
	(void)argv;
	unload_allowed_uid = taiHookFunctionImportForKernel(KERNEL_PID, 
		&unload_allowed_hook,     // Output a reference
		"SceKernelModulemgr",     // Name of module being hooked
		0x11F9B314,               // NID specifying SceSblACMgrForKernel
		0xBBA13D9C,               // Function NID
		unload_allowed_patched);  // Name of the hook function

	return SCE_KERNEL_START_SUCCESS;
}
void _start() __attribute__ ((weak, alias ("module_start")));

int module_stop() {
	taiHookReleaseForKernel(unload_allowed_uid, unload_allowed_hook);

	return SCE_KERNEL_STOP_SUCCESS;
}
