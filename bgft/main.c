#include <stddef.h>
#include <sys/mman.h>
#include "ps4-libjbc/jailbreak.h"

int do_download_pkg(const char* tgt_path);

enum bgft_task_option_t {
	BGFT_TASK_OPTION_NONE = 0x0,
	BGFT_TASK_OPTION_DELETE_AFTER_UPLOAD = 0x1,
	BGFT_TASK_OPTION_INVISIBLE = 0x2,
	BGFT_TASK_OPTION_ENABLE_PLAYGO = 0x4,
	BGFT_TASK_OPTION_FORCE_UPDATE = 0x8,
	BGFT_TASK_OPTION_REMOTE = 0x10,
	BGFT_TASK_OPTION_COPY_CRASH_REPORT_FILES = 0x20,
	BGFT_TASK_OPTION_DISABLE_INSERT_POPUP = 0x40,
	BGFT_TASK_OPTION_DISABLE_CDN_QUERY_PARAM = 0x10000,
};

struct bgft_download_param {
	int user_id;
	int entitlement_type;
	const char* id;
	const char* content_url;
	const char* content_ex_url;
	const char* content_name;
	const char* icon_path;
	const char* sku_id;
	enum bgft_task_option_t option;
	const char* playgo_scenario_id;
	const char* release_date;
	const char* package_type;
	const char* package_sub_type;
	unsigned long package_size;
};

struct bgft_download_param_ex {
	struct bgft_download_param param;
	unsigned int slot;
};

struct bgft_task_progress_internal {
	unsigned int bits;
	int error_result;
	unsigned long length;
	unsigned long transferred;
	unsigned long length_total;
	unsigned long transferred_total;
	unsigned int num_index;
	unsigned int num_total;
	unsigned int rest_sec;
	unsigned int rest_sec_total;
	int preparing_percent;
	int local_copy_percent;
};

#define BGFT_INVALID_TASK_ID (-1)

struct bgft_init_params {
	void* mem;
	unsigned long size;
};

void* dlopen(const char*, int);
void* dlsym(void*, const char*);

#define PATH "/user/home/app.pkg"

asm("clear_stack:\nmov $0x800,%ecx\nmovabs $0xdead000000000000,%rax\n.L1:\npush %rax\nloop .L1\nadd $0x4000,%rsp\nret");
void clear_stack(void);

int main()
{
    struct jbc_cred cred;
    jbc_get_cred(&cred);
    jbc_jailbreak_cred(&cred);
    cred.jdir = 0;
    cred.sceProcType = 0x3800000000000010;
    cred.sonyCred = 0x40001c0000000000;
    cred.sceProcCap = 0x900000000000ff00;
    jbc_set_cred(&cred);
    if(do_download_pkg(PATH))
        *(void* volatile*)0;
    int rv;
    clear_stack();
    void* bgft = dlopen("/system/common/lib/libSceBgft.sprx", 0);
    int(*sceBgftInitialize)(struct bgft_init_params*) = dlsym(bgft, "sceBgftServiceIntInit");
    int(*sceBgftDownloadRegisterTaskByStorageEx)(struct bgft_download_param_ex*, int*) = dlsym(bgft, "sceBgftServiceIntDownloadRegisterTaskByStorageEx");
    int(*sceBgftDownloadStartTask)(int) = dlsym(bgft, "sceBgftServiceIntDownloadStartTask");
    void* aiu = dlopen("/system/common/lib/libSceAppInstUtil.sprx", 0);
    int(*sceAppInstUtilInitialize)(void) = dlsym(aiu, "sceAppInstUtilInitialize");
    int(*sceAppInstUtilGetTitleIdFromPkg)(const char*, char*, int*) = dlsym(aiu, "sceAppInstUtilGetTitleIdFromPkg");
    int(*sceAppInstUtilAppUnInstall)(const char*) = dlsym(aiu, "sceAppInstUtilAppUnInstall");
    rv = sceAppInstUtilInitialize();
    char titleid[16];
    //credit: LightningMods
    int is_app = 0;
    sceAppInstUtilGetTitleIdFromPkg(PATH, titleid, &is_app);
    struct bgft_init_params ip = {
        .mem = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0),
        .size = 0x100000,
    };
    rv = sceBgftInitialize(&ip);
    struct bgft_download_param_ex params = {
        .param = {
            .entitlement_type = 5,
            .id = "",
            .content_url = "/user/home/app.pkg",
            .content_name = "app.pkg",
            .icon_path = "",
            .playgo_scenario_id = "0",
            .option = BGFT_TASK_OPTION_DISABLE_CDN_QUERY_PARAM | BGFT_TASK_OPTION_FORCE_UPDATE | BGFT_TASK_OPTION_DELETE_AFTER_UPLOAD,
        },
        .slot = 0,
    };
    int task = BGFT_INVALID_TASK_ID;
    while((rv = sceBgftDownloadRegisterTaskByStorageEx(&params, &task)) == 0x80990088)
        rv = sceAppInstUtilAppUnInstall(titleid);
    rv = sceBgftDownloadStartTask(task);
    return 0;
}
