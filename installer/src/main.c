#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/devctl.h>
#include <psp2/ctrl.h>
#include <psp2/shellutil.h>
#include <psp2/net/http.h>
#include <psp2/net/net.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/net/netctl.h>
#include <psp2/io/stat.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>

#include "debug_screen.h"
#include "enso.h"
#include "version.h"
#include "sha256.h"

#define printf psvDebugScreenPrintf
#define ARRAYSIZE(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

int _vshSblAimgrGetConsoleId(char cid[32]);
int sceSblSsUpdateMgrSetBootMode(int x);
int vshPowerRequestColdReset(void);

enum {
	SCREEN_WIDTH = 960,
	SCREEN_HEIGHT = 544,
	PROGRESS_BAR_WIDTH = SCREEN_WIDTH,
	PROGRESS_BAR_HEIGHT = 10,
	LINE_SIZE = SCREEN_WIDTH,
};

static unsigned buttons[] = {
	SCE_CTRL_SELECT,
	SCE_CTRL_START,
	SCE_CTRL_UP,
	SCE_CTRL_RIGHT,
	SCE_CTRL_DOWN,
	SCE_CTRL_LEFT,
	SCE_CTRL_LTRIGGER,
	SCE_CTRL_RTRIGGER,
	SCE_CTRL_TRIANGLE,
	SCE_CTRL_CIRCLE,
	SCE_CTRL_CROSS,
	SCE_CTRL_SQUARE,
};

const char check_cid[16] = BUILD_CID;

uint32_t get_key(void) {
	static unsigned prev = 0;
	SceCtrlData pad;
	while (1) {
		memset(&pad, 0, sizeof(pad));
		sceCtrlPeekBufferPositive(0, &pad, 1);
		unsigned new = prev ^ (pad.buttons & prev);
		prev = pad.buttons;
		for (size_t i = 0; i < sizeof(buttons)/sizeof(*buttons); ++i)
			if (new & buttons[i])
				return buttons[i];

		sceKernelDelayThread(1000); // 1ms
	}
}

void press_exit(void) {
	printf("Press any key to exit this application.\n");
	get_key();
	sceKernelExitProcess(0);
}

void press_reboot(void) {
	printf("Press any key to reboot.\n");
	get_key();
	vshPowerRequestColdReset();
}

int g_kernel_module, g_user_module, g_kernel2_module;

#define APP_PATH "ux0:app/MLCL00003/"

int load_helper(void) {
	int ret = 0;

	tai_module_args_t args = {0};
	args.size = sizeof(args);
	args.args = 0;
	args.argp = "";

	if ((ret = g_kernel2_module = taiLoadStartKernelModuleForUser(APP_PATH "kernel2.skprx", &args)) < 0) {
		printf("Failed to load kernel workaround: 0x%08x\n", ret);
		return -1;
	}

	if ((ret = g_kernel_module = taiLoadStartKernelModuleForUser(APP_PATH "emmc_helper.skprx", &args)) < 0) {
		printf("Failed to load kernel module: 0x%08x\n", ret);
		return -1;
	}

	if ((ret = g_user_module = sceKernelLoadStartModule(APP_PATH "emmc_helper.suprx", 0, NULL, 0, NULL, NULL)) < 0) {
		printf("Failed to load user module: 0x%08x\n", ret);
		return -1;
	}

	return 0;
}

int stop_helper(void) {
	tai_module_args_t args = {0};
	args.size = sizeof(args);
	args.args = 0;
	args.argp = "";

	int ret = 0;
	int res = 0;

	if (g_user_module > 0) {
		ret = sceKernelStopUnloadModule(g_user_module, 0, NULL, 0, NULL, NULL);
		if (ret < 0) {
			printf("Failed to unload user module: 0x%08x\n", ret);
			return -1;
		}
	}

	if (g_kernel_module > 0) {
		ret = taiStopUnloadKernelModuleForUser(g_kernel_module, &args, NULL, &res);
		if (ret < 0) {
			printf("Failed to unload kernel module: 0x%08x\n", ret);
			return -1;
		}
	}

	if (g_kernel2_module > 0) {
		ret = taiStopUnloadKernelModuleForUser(g_kernel2_module, &args, NULL, &res);
		if (ret < 0) {
			printf("Failed to unload kernel workaround module: 0x%08x\n", ret);
			return -1;
		}
	}

	return ret;
}

int lock_system(void) {
	int ret = 0;

	printf("Locking system...\n");
	ret = sceShellUtilInitEvents(0);
	if (ret < 0) {
		printf("failed: 0x%08X\n", ret);
		return -1;
	}
	ret = sceShellUtilLock(7);
	if (ret < 0) {
		printf("failed: 0x%08X\n", ret);
		return -1;
	}
	ret = sceKernelPowerLock(0);
	if (ret < 0) {
		printf("failed: 0x%08X\n", ret);
		return -1;
	}

	return 0;
}

int unlock_system(void) {
	sceKernelPowerUnlock(0);
	sceShellUtilUnlock(7);

	return 0;
}

void draw_rect(int x, int y, int width, int height, uint32_t color) {
	void *base = psvDebugScreenBase();

	for (int j = y; j < y + height; ++j)
		for (int i = x; i < x + width; ++i)
			((uint32_t*)base)[j * LINE_SIZE + i] = color;
}

int g_tpl;

int download_file(const char *src, const char *dst, uint8_t *expect_hash) {
	int ret;

	int conn = sceHttpCreateConnectionWithURL(g_tpl, src, 0);
	if (conn < 0) {
		printf("sceHttpCreateConnectionWithURL: 0x%x\n", conn);
		return conn;
	}
	int req = sceHttpCreateRequestWithURL(conn, 0, src, 0);
	if (req < 0) {
		printf("sceHttpCreateRequestWithURL: 0x%x\n", req);
		sceHttpDeleteConnection(conn);
		return req;
	}
	ret = sceHttpSendRequest(req, NULL, 0);
	if (ret < 0) {
		printf("sceHttpSendRequest: 0x%x\n", ret);
		goto end;
	}
	static unsigned char buf[4096];

	uint64_t length = 0;
	ret = sceHttpGetResponseContentLength(req, &length);

	int fd = sceIoOpen(dst, SCE_O_TRUNC | SCE_O_CREAT | SCE_O_WRONLY, 6);
	int total_read = 0;
	if (fd < 0) {
		printf("sceIoOpen: 0x%x\n", fd);
		ret = fd;
		goto end;
	}

	SHA256_CTX ctx = {0};
	sha256_init(&ctx);

	// draw progress bar background
	draw_rect(0, SCREEN_HEIGHT - PROGRESS_BAR_HEIGHT, PROGRESS_BAR_WIDTH, PROGRESS_BAR_HEIGHT, 0xFF666666);
	while (1) {
		int read = sceHttpReadData(req, buf, sizeof(buf));
		if (read < 0) {
			printf("sceHttpReadData error! 0x%x\n", read);
			ret = read;
			goto end2;
		}
		if (read == 0)
			break;
		ret = sceIoWrite(fd, buf, read);
		if (ret < 0 || ret != read) {
			printf("sceIoWrite error! 0x%x\n", ret);
			goto end2;
		}
		sha256_update(&ctx, buf, read);
		total_read += read;
		draw_rect(1, SCREEN_HEIGHT - PROGRESS_BAR_HEIGHT + 1, ((uint64_t)(PROGRESS_BAR_WIDTH - 2)) * total_read / length, PROGRESS_BAR_HEIGHT - 2, 0xFFFFFFFF);
	}

	uint8_t hash[32] = {0};
	sha256_final(&ctx, hash);
	if (memcmp(hash, expect_hash, sizeof(hash)) != 0) {
		printf("the file got corrupted in transit\n");
		ret = -1;
	} else {
		ret = 0;
	}

end2:
	sceIoClose(fd);
end:
	sceHttpDeleteRequest(req);
	sceHttpDeleteConnection(conn);

	return ret;
}

int init_net(void) {
	SceNetInitParam netInitParam;
	int ret;
	void *base;

	ret = sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_NET);
	if (ret < 0) {
		printf("SCE_SYSMODULE_PROMOTER_UTIL(SCE_SYSMODULE_NET): %x\n", ret);
		return -1;
	}

	ret = sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_HTTP);
	if (ret < 0) {
		printf("SCE_SYSMODULE_PROMOTER_UTIL(SCE_SYSMODULE_HTTP): %x\n", ret);
		return -1;
	}

	ret = sceHttpInit(1*1024*1024);
	if (ret < 0) {
		printf("sceHttpInit(): %x\n", ret);
		return -1;
	}

	int block = sceKernelAllocMemBlock("net", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, 1*1024*1024, NULL);
	if (block < 0) {
		printf("failed to allocate net block: 0x%08x\n", block);
		return -1;
	}
	ret = sceKernelGetMemBlockBase(block, &base);

	netInitParam.memory = base;
	netInitParam.size = 1*1024*1024;
	netInitParam.flags = 0;
	ret = sceNetInit(&netInitParam);
	if (ret < 0) {
		printf("sceNetInit(): %x\n", ret);
		return -1;		
	}

	ret = sceNetCtlInit();
	if (ret < 0) {
		printf("sceNetCtlInit(): %x\n", ret);
		return -1;
	}

	g_tpl = sceHttpCreateTemplate("enso installer", 2, 1);
	if (g_tpl < 0) {
		printf("sceHttpCreateTemplate: 0x%x\n", g_tpl);
		return -1;		
	}
	sceHttpSetAutoRedirect(g_tpl, 1);

	return 0;
}

int extract(const char *pup, const char *psp2swu) {
	int inf, outf;

	if ((inf = sceIoOpen(pup, SCE_O_RDONLY, 0)) < 0) {
		return -1;
	}

	if ((outf = sceIoOpen(psp2swu, SCE_O_CREAT | SCE_O_WRONLY | SCE_O_TRUNC, 6)) < 0) {
		return -1;
	}

	int ret = -1;
	int count;

	if (sceIoLseek(inf, 0x18, SCE_SEEK_SET) < 0) {
		goto end;
	}

	if (sceIoRead(inf, &count, 4) < 4) {
		goto end;
	}

	if (sceIoLseek(inf, 0x80, SCE_SEEK_SET) < 0) {
		goto end;
	}

	struct {
		uint64_t id;
		uint64_t off;
		uint64_t len;
		uint64_t field_18;
	} __attribute__((packed)) file_entry;

	for (int i = 0; i < count; i++) {

		if (sceIoRead(inf, &file_entry, sizeof(file_entry)) != sizeof(file_entry)) {
			goto end;
		}

		if (file_entry.id == 0x200) {
			break;
		}
	}

	if (file_entry.id == 0x200) {
		char buffer[1024];
		size_t rd;

		if (sceIoLseek(inf, file_entry.off, SCE_SEEK_SET) < 0) {
			goto end;
		}

		while (file_entry.len && (rd = sceIoRead(inf, buffer, sizeof(buffer))) > 0) {
			if (rd > file_entry.len) {
				rd = file_entry.len;
			}
			sceIoWrite(outf, buffer, rd);
			file_entry.len -= rd;
		}

		if (file_entry.len == 0) {
			ret = 0;
		}
	}

end:
	sceIoClose(inf);
	sceIoClose(outf);
	return ret;
}

int reinstall_firmware(void) {
	int ret = 0;

	stop_helper();
	unlock_system();
	sceKernelPowerLock(0); // don't want the screen to turn off during download

	ret = init_net();
	if (ret < 0) {
		printf("failed to init network functions\n");
		goto cleanup;
	}

	// delete old update files
	const char *files[] = {
		"ud0:PSP2UPDATE/PSP2UPDAT.PUP",
		"ud0:PSP2UPDATE/PSP2UPDAT.PUP_",
		"ud0:PSP2UPDATE/psp2swu.self",
		"ud0:PSP2UPDATE/psp2swu.self_"
	};
	for (size_t i = 0; i < ARRAYSIZE(files); ++i)
		sceIoRemove(files[i]);
	for (size_t i = 0; i < ARRAYSIZE(files); ++i) {
		int fd = sceIoOpen(files[i], SCE_O_RDONLY, 0);
		if (fd != (int)0x80010002) {
			printf("failed to clean up old files: 0x%08x\n", fd);
			return -1;
		}
	}

	// make sure directory is present
	sceIoMkdir("ud0:PSP2UPDATE", 0777);

	uint8_t psp2updat_hash[] = { 0x8c, 0xc2, 0xe2, 0x66, 0x66, 0x26, 0xc4, 0xff, 0x8f, 0x58, 0x2b, 0xf2, 0x09, 0x47, 0x35, 0x26,
		0xe8, 0x25, 0xe2, 0xa5, 0xe3, 0x8e, 0x39, 0xb2, 0x59, 0xa8, 0xa4, 0x6e, 0x25, 0xef, 0x37, 0x1c };

	printf("Downloading PSP2UPDAT.PUP...\n");
	if (download_file("http://update.henkaku.xyz/update/PSP2UPDAT.FULL.360.PUP",
			"ud0:PSP2UPDATE/PSP2UPDAT.PUP_", psp2updat_hash) < 0) {
		printf("Failed to download update file.\n");
		ret = -1;
		goto cleanup;
	}

	printf("Extracting updater...\n");
	extract("ud0:PSP2UPDATE/PSP2UPDAT.PUP_", "ud0:PSP2UPDATE/psp2swu.self_");

	if ((ret = sceIoRename("ud0:PSP2UPDATE/PSP2UPDAT.PUP_", "ud0:PSP2UPDATE/PSP2UPDAT.PUP")) < 0) {
		printf("failed to rename PSP2UPDAT: 0x%08x\n", ret);
		ret = -1;
		goto cleanup;
	}
	if ((ret = sceIoRename("ud0:PSP2UPDATE/psp2swu.self_", "ud0:PSP2UPDATE/psp2swu.self")) < 0) {
		printf("failed to rename psp2swu: 0x%08x\n", ret);
		ret = -1;
		goto cleanup;
	}

	sceIoSync("ud0:", 0);
	sceIoSync("ud0:PSP2UPDATE/PSP2UPDAT.PUP", 0);
	sceIoSync("ud0:PSP2UPDATE/psp2swu.self", 0);

	printf("Rebooting to update in 5 seconds...\n");
	printf("Close this app now if you changed your mind.\n");
	sceKernelPowerUnlock(0);

	sceKernelDelayThread(5 * 1000 * 1000);

	sceSblSsUpdateMgrSetBootMode(48);
	vshPowerRequestColdReset();

	ret = 0;

cleanup:
	return ret;
}

int do_install(void) {
	int ret = 0;

	if (lock_system() < 0)
		return -1;

	printf("Checking MBR... ");
	ret = ensoCheckMBR();
	if (ret < 0) {
		printf("failed\n");
		goto err;
	}
	printf("ok!\n");

	printf("Checking os0... ");
	ret = ensoCheckOs0();
	if (ret < 0) {
		printf("failed\n");
		printf("\nos0 modifications detected.\nYou should reinstall 3.60 and try again.\n");

		printf("Press X to download and install 3.60 PUP, any other key to exit.\n");
		if (get_key() == SCE_CTRL_CROSS) {
			if (reinstall_firmware() < 0) {
				printf("failed to trigger a reinstall\n");
				ret = -1;
			}
		}

		goto err;
	}
	printf("ok!\n");
	printf("\n");

	printf("Checking for previous installation... ");
	ret = ensoCheckBlocks();
	if (ret < 0) {
		printf("failed\n");
		goto err;
	}
	printf("ok!\n", ret);
	if (ret == 0) {
		// all good, blocks are empty
	} else if (ret == E_PREVIOUS_INSTALL) {
		printf("Previous installation was detected and will be overwritten.\nPress X to continue, any other key to exit.\n");
		if (get_key() != SCE_CTRL_CROSS)
			goto err;
	} else if (ret == E_MBR_BUT_UNKNOWN) {
		printf("MBR was detected but installation checksum does not match.\nA dump was created at %s.\nPress X to continue, any other key to exit.\n", BLOCKS_OUTPUT);
		if (get_key() != SCE_CTRL_CROSS)
			goto err;
	} else if (ret == E_UNKNOWN_DATA) {
		printf("Unknown data was detected.\nA dump was created at %s.\nThe installation will be aborted.\n", BLOCKS_OUTPUT);
		goto err;
	} else {
		printf("Unknown error code.\n");
		goto err;
	}

	printf("Writing config... ");
	ret = ensoWriteConfig();
	if (ret < 0) {
		printf("failed\n");
		goto err;
	}
	printf("ok!\n");

	printf("Writing blocks... ");
	ret = ensoWriteBlocks();
	if (ret < 0) {
		printf("failed\n");
		goto err;
	}
	printf("ok!\n");

	printf("Writing MBR... ");
	ret = ensoWriteMBR();
	if (ret < 0) {
		printf("failed\n");
		goto err;
	}
	printf("ok!\n");

	printf("\nThe installation was completed successfully.\n");

	unlock_system();
	return 0;
err:
	unlock_system();
	return -1;
}

int do_uninstall(void) {
	int ret = 0;

	printf("Checking MBR in block 1... ");
	ret = ensoCheckRealMBR();
	if (ret < 0) {
		printf("failed\n");
		return -1;
	}
	printf("ok!\n");

	printf("Uninstalling MBR patch... ");
	ret = ensoUninstallMBR();
	if (ret < 0) {
		printf("failed\n");
		return -1;
	}
	printf("ok!\n");

	printf("Cleaning up payload blocks... ");
	ret = ensoCleanUpBlocks();
	if (ret < 0) {
		printf("failed\n");
		return -1;
	}
	printf("ok!\n");

	printf("Deleting boot config... ");
	sceIoRemove("ur0:tai/boot_config.txt");
	printf("ok!\n");

	return 0;
}

int do_reinstall_config(void) {
	int ret = 0;

	printf("Writing config... ");
	ret = ensoWriteConfig();
	if (ret < 0) {
		printf("failed\n");
		return -1;
	}
	printf("ok!\n");

	return 0;
}

int check_build(void) {
	if (BUILD_PERSONALIZED) {
		char right_cid[16];
		char cur_cid[16];
		for (int i = 0; i < 16; i++) {
			right_cid[i] = check_cid[i] ^ 0xAA; // super leet encryption
		}
		_vshSblAimgrGetConsoleId(cur_cid);
		if (memcmp(cur_cid, right_cid, 16) == 0) {
			return 1;
		} else {
			return 0;
		}
	} else {
		return 1;
	}
}

int check_safe_mode(void) {
	if (sceIoDevctl("ux0:", 0x3001, NULL, 0, NULL, 0) == 0x80010030) {
		return 1;
	} else {
		return 0;
	}
}

int check_henkaku(void) {
	int fd;

	if ((fd = sceIoOpen("ur0:tai/taihen.skprx", SCE_O_RDONLY, 0)) < 0) {
		return 0;
	}
	sceIoClose(fd);
	if ((fd = sceIoOpen("ur0:tai/henkaku.skprx", SCE_O_RDONLY, 0)) < 0) {
		return 0;
	}
	sceIoClose(fd);
	return 1;
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	int should_reboot = 0;
	int ret = 0;

	psvDebugScreenInit();

	if (!check_build()) {
		return 0;
	}

	printf("Built On: %s\n\n", BUILD_DATE);

	if (check_safe_mode()) {
		printf("Please disable HENkaku Safe Mode from Settings before running this installer.\n\n");
		press_exit();
	}

	if (!check_henkaku()) {
		printf("Your HENkaku version is too old! Please install R10 from https://henkaku.xyz/go/ (not the offline installer!)\n\n");
		press_exit();
	}

#if BUILD_PERSONALIZED
	printf("Please visit https://enso.henkaku.xyz/beta/ for installation instructions.\n\n");

	uint32_t sequence[] = { SCE_CTRL_CROSS, SCE_CTRL_TRIANGLE, SCE_CTRL_SQUARE, SCE_CTRL_CIRCLE };
	for (size_t i = 0; i < sizeof(sequence)/sizeof(*sequence); ++i) {
		if (get_key() != sequence[i])
			press_exit();
	}
#endif

	printf("This software will make PERMANENT modifications to your Vita. If anything goes wrong, \n"
		   "there is NO RECOVERY (not even with a hardware flasher). The creators provide this \n"
		   "tool \"as is\", without warranty of any kind, express or implied and cannot be held \n"
		   "liable for any damage done.\n\n");
	printf("Press CIRCLE to accept these terms or any other key to not accept.\n\n");

	if (get_key() != SCE_CTRL_CIRCLE) {
		press_exit();
	}

	ret = load_helper();
	if (ret < 0)
		goto cleanup;

	printf("Options:\n\n");
	printf("  CROSS      Install/reinstall the hack.\n");
	printf("  TRIANGLE   Uninstall the hack.\n");
	printf("  SQUARE     Fix boot configuration (choose this if taiHEN isn't loading on boot).\n");
	printf("  CIRCLE     Exit without doing anything.\n\n");

again:
	switch (get_key()) {
	case SCE_CTRL_CROSS:
		ret = do_install();
		should_reboot = 1;
		break;
	case SCE_CTRL_TRIANGLE:
		ret = do_uninstall();
		should_reboot = 1;
		break;
	case SCE_CTRL_SQUARE:
		ret = do_reinstall_config();
		break;
	case SCE_CTRL_CIRCLE:
		break;
	default:
		goto again;
	}

	if (ret < 0) {
		printf("\nAn error has occurred.\n");
		printf("The log file can be found at ux0:data/enso.log\n\n");
		should_reboot = 0;
	} else {
		printf("Success.\n\n");
	}

cleanup:
	stop_helper();

	if (should_reboot) {
		press_reboot();
	} else {
		press_exit();
	}

	return 0;
}
