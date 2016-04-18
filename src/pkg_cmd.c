/*
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <dirent.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/time.h>

#include <glib.h>
#include <glib-object.h>
#include <sqlite3.h>

#include <pkgmgr-info.h>
/* For multi-user support */
#include <tzplatform_config.h>

#include <package-manager.h>
#include <package-manager-types.h>
#include "delta.h"

#define PKG_TOOL_VERSION	"0.1"
#define APP_INSTALLATION_PATH_RW	tzplatform_getenv(TZ_USER_APP)
#define MAX_QUERY_LEN	4096

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#define OPTVAL_GLOBAL 1000
#define OPTVAL_ADD_BLACKLIST 1001
#define OPTVAL_REMOVE_BLACKLIST 1002
#define OPTVAL_CHECK_BLACKLIST 1003

static int __process_request(uid_t uid);
static void __print_usage();
static int __is_app_installed(char *pkgid, uid_t uid);
static int __return_cb(uid_t target_uid, int req_id, const char *pkg_type,
		       const char *pkgid, const char *key, const char *val,
		       const void *pmsg, void *data);
static int __convert_to_absolute_path(char *path);

/* Supported options */
/* Note: 'G' is reserved */
const char *short_options = "iurwmcgCkaADL:lsd:p:t:n:T:S:e:M:X:Y:Z:qhG";
const struct option long_options[] = {
	{"install", 0, NULL, 'i'},
	{"uninstall", 0, NULL, 'u'},
	{"reinstall", 0, NULL, 'r'},
	{"mount-install", 0, NULL, 'w'},
	{"move", 0, NULL, 'm'},
	{"clear", 0, NULL, 'c'},
	{"getsize", 0, NULL, 'g'},
	{"activate", 0, NULL, 'A'},
	{"deactivate", 0, NULL, 'D'},
	{"activate with Label", 1, NULL, 'L'},
	{"check", 0, NULL, 'C'},
	{"kill", 0, NULL, 'k'},
	{"app-path", 0, NULL, 'a'},
	{"list", 0, NULL, 'l'},
	{"show", 0, NULL, 's'},
	{"descriptor", 1, NULL, 'd'},
	{"package-path", 1, NULL, 'p'},
	{"old_pkg", 1, NULL, 'X'},
	{"new_pkg", 1, NULL, 'Y'},
	{"delta_pkg", 1, NULL, 'Z'},
	{"package-type", 1, NULL, 't'},
	{"package-name", 1, NULL, 'n'},
	{"move-type", 1, NULL, 'T'},
	{"getsize-type", 1, NULL, 'T'},
	{"csc", 1, NULL, 'S'},
	{"tep-path", 1, NULL, 'e'},
	{"tep-move", 1, NULL, 'M'},
	{"global", 0, NULL, OPTVAL_GLOBAL},
	{"quiet", 0, NULL, 'q'},
	{"help", 0, NULL, 'h'},
	{"add-blacklist", 1, NULL, OPTVAL_ADD_BLACKLIST},
	{"remove-blacklist", 1, NULL, OPTVAL_REMOVE_BLACKLIST},
	{"check-blacklist", 1, NULL, OPTVAL_CHECK_BLACKLIST},
	{"debug-mode", 0, NULL, 'G'},
	{0, 0, 0, 0}		/* sentinel */
};

enum pm_tool_request_e {
	INSTALL_REQ = 1,
	UNINSTALL_REQ,
	REINSTALL_REQ,
	MOUNT_INSTALL_REQ,
	CSC_REQ,
	GETSIZE_REQ,
	CLEAR_REQ,
	MOVE_REQ,
	ACTIVATE_REQ,
	DEACTIVATE_REQ,
	APPPATH_REQ,
	CHECKAPP_REQ,
	KILLAPP_REQ,
	LIST_REQ,
	SHOW_REQ,
	HELP_REQ,
	CREATE_DELTA,
	ADD_BLACKLIST_REQ,
	REMOVE_BLACKLIST_REQ,
	CHECK_BLACKLIST_REQ,
};
typedef enum pm_tool_request_e req_type;

struct pm_tool_args_t {
	req_type request;
	char pkg_path[PATH_MAX];
	char pkg_type[PKG_TYPE_STRING_LEN_MAX];
	char pkgid[PKG_NAME_STRING_LEN_MAX];
	char des_path[PATH_MAX];
	char pkg_old[PATH_MAX];
	char pkg_new[PATH_MAX];
	char delta_pkg[PATH_MAX];
	char resolved_path_pkg_old[PATH_MAX];
	char resolved_path_pkg_new[PATH_MAX];
	char resolved_path_delta_pkg[PATH_MAX];
	char label[PKG_NAME_STRING_LEN_MAX];
	char tep_path[PATH_MAX];
	char tep_move[PKG_NAME_STRING_LEN_MAX];

	int global;
	int type;
	int result;
};
typedef struct pm_tool_args_t pm_tool_args;
pm_tool_args data;

static GMainLoop *main_loop = NULL;

static void __error_no_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL)
		return;
	switch (errnumber) {
	case PKGCMD_ERRCODE_UNZIP_ERROR:
		*errstr = PKGCMD_ERRCODE_UNZIP_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_SECURITY_ERROR:
		*errstr = PKGCMD_ERRCODE_SECURITY_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_REGISTER_ERROR:
		*errstr = PKGCMD_ERRCODE_REGISTER_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_PRIVILEGE_ERROR:
		*errstr = PKGCMD_ERRCODE_PRIVILEGE_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_PARSE_ERROR:
		*errstr = PKGCMD_ERRCODE_PARSE_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_RECOVERY_ERROR:
		*errstr = PKGCMD_ERRCODE_RECOVERY_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_DELTA_ERROR:
		*errstr = PKGCMD_ERRCODE_DELTA_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_APP_DIR_ERROR:
		*errstr = PKGCMD_ERRCODE_APP_DIR_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_CONFIG_ERROR:
		*errstr = PKGCMD_ERRCODE_CONFIG_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_SIGNATURE_ERROR:
		*errstr = PKGCMD_ERRCODE_SIGNATURE_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_SIGNATURE_INVALID:
		*errstr = PKGCMD_ERRCODE_SIGNATURE_INVALID_STR;
		break;
	case PKGCMD_ERRCODE_CERT_ERROR:
		*errstr = PKGCMD_ERRCODE_CERT_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_AUTHOR_CERT_NOT_MATCH:
		*errstr = PKGCMD_ERRCODE_AUTHOR_CERT_NOT_MATCH_STR;
		break;
	case PKGCMD_ERRCODE_AUTHOR_CERT_NOT_FOUND:
		*errstr = PKGCMD_ERRCODE_AUTHOR_CERT_NOT_FOUND_STR;
		break;
	case PKGCMD_ERRCODE_ICON_ERROR:
		*errstr = PKGCMD_ERRCODE_ICON_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_ICON_NOT_FOUND:
		*errstr = PKGCMD_ERRCODE_ICON_NOT_FOUND_STR;
		break;
	case PKGCMD_ERRCODE_MANIFEST_ERROR:
		*errstr = PKGCMD_ERRCODE_MANIFEST_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_MANIFEST_NOT_FOUND:
		*errstr = PKGCMD_ERRCODE_MANIFEST_NOT_FOUND_STR;
		break;
	case PKGCMD_ERRCODE_PACKAGE_NOT_FOUND:
		*errstr = PKGCMD_ERRCODE_PACKAGE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERRCODE_OPERATION_NOT_ALLOWED:
		*errstr = PKGCMD_ERRCODE_OPERATION_NOT_ALLOWED_STR;
		break;
	case PKGCMD_ERRCODE_OUT_OF_SPACE:
		*errstr = PKGCMD_ERRCODE_OUT_OF_SPACE_STR;
		break;
	case PKGCMD_ERRCODE_INVALID_VALUE:
		*errstr = PKGCMD_ERRCODE_INVALID_VALUE_STR;
		break;
	case PKGCMD_ERRCODE_ERROR:
		*errstr = PKGCMD_ERRCODE_ERROR_STR;
		break;
	case PKGCMD_ERRCODE_OK:
		*errstr = PKGCMD_ERRCODE_OK_STR;
		break;
	default:
		*errstr = "Undefined Error";
		break;
	}
}

static int __return_cb(uid_t target_uid, int req_id, const char *pkg_type,
		       const char *pkgid, const char *key, const char *val,
		       const void *pmsg, void *priv_data)
{
	int ret_val;
	char delims[] = ":";
	char *ret_result = NULL;

	if (strncmp(key, "error", strlen("error")) == 0) {
		ret_val = atoi(val);
		data.result = ret_val;

		ret_result = strstr((char *)val, delims);
		if (ret_result)
			printf("__return_cb req_id[%d] pkg_type[%s] pkgid[%s] key[%s] val[%d] error message: %s\n",
					   req_id, pkg_type, pkgid, key, ret_val, ret_result);
		else
			printf("__return_cb req_id[%d] pkg_type[%s] pkgid[%s] key[%s] val[%d]\n",
					   req_id, pkg_type, pkgid, key, ret_val);
	} else
		printf("__return_cb req_id[%d] pkg_type[%s] "
			   "pkgid[%s] key[%s] val[%s]\n",
			   req_id, pkg_type, pkgid, key, val);

	if (strncmp(key, "end", strlen("end")) == 0) {
		if ((strncmp(val, "fail", strlen("fail")) == 0) && data.result == 0)
			data.result = PKGCMD_ERRCODE_ERROR;
		g_main_loop_quit(main_loop);
	}

	return 0;
}

static int __app_return_cb(uid_t target_uid, int req_id, const char *pkg_type,
		       const char *pkgid, const char *appid, const char *key, const char *val,
		       const void *pmsg, void *priv_data)
{
	int ret_val;

	if (strncmp(key, "error", strlen("error")) == 0) {
		ret_val = atoi(val);
		data.result = ret_val;
	}

	printf("__app_return_cb req_id[%d] pkg_type[%s] pkgid[%s] appid[%s] " \
				"key[%s] val[%s]\n",
				req_id, pkg_type, pkgid, appid, key, val);

	if (strncmp(key, "end", strlen("end")) == 0) {
		if ((strncmp(val, "fail", strlen("fail")) == 0) && data.result == 0)
			data.result = PKGCMD_ERRCODE_ERROR;
		g_main_loop_quit(main_loop);
	}

	return 0;
}

static int __convert_to_absolute_path(char *path)
{
	char abs[PKG_NAME_STRING_LEN_MAX] = {'\0'};
	char temp[PKG_NAME_STRING_LEN_MAX] = {'\0'};
	char *ptr = NULL;
	if (path == NULL) {
		printf("path is NULL\n");
		return -1;
	}
	strncpy(temp, path, PKG_NAME_STRING_LEN_MAX - 1);
	if (strchr(path, '/') == NULL) {
		if (getcwd(abs, PKG_NAME_STRING_LEN_MAX - 1) == NULL) {
			printf("getcwd() failed\n");
			return -1;
		}
		memset(data.pkg_path, '\0', PKG_NAME_STRING_LEN_MAX);
		snprintf(data.pkg_path, PKG_NAME_STRING_LEN_MAX - 1, "%s/%s", abs, temp);
		return 0;
	}
	if (strncmp(path, "./", 2) == 0) {
		ptr = temp;
		if (getcwd(abs, PKG_NAME_STRING_LEN_MAX - 1) == NULL) {
			printf("getcwd() failed\n");
			return -1;
		}
		ptr = ptr + 2;
		memset(data.pkg_path, '\0', PKG_NAME_STRING_LEN_MAX);
		snprintf(data.pkg_path, PKG_NAME_STRING_LEN_MAX - 1, "%s/%s", abs, ptr);
		return 0;
	}
	return 0;
}

static int __convert_to_absolute_tep_path(char *path)
{
	char abs[PATH_MAX] = {'\0'};
	char temp[PATH_MAX] = {'\0'};
	char *ptr = NULL;
	if (path == NULL) {
		printf("path is NULL\n");
		return -1;
	}
	strncpy(temp, path, PATH_MAX - 1);
	if (strchr(path, '/') == NULL) {
		if (getcwd(abs, PATH_MAX - 1) == NULL || abs[0] == '\0') {
			printf("getcwd() failed\n");
			return -1;
		}
		memset(data.tep_path, '\0', PATH_MAX);
		snprintf(data.tep_path, PATH_MAX - 1, "%s/%s", abs, temp);
		return 0;
	}
	if (strncmp(path, "./", 2) == 0) {
		ptr = temp;
		if (getcwd(abs, PATH_MAX - 1) == NULL || abs[0] == '\0') {
			printf("getcwd() failed\n");
			return -1;
		}
		ptr = ptr + 2;
		memset(data.tep_path, '\0', PATH_MAX);
		snprintf(data.tep_path, PATH_MAX - 1, "%s/%s", abs, ptr);
		return 0;
	}
	return 0;
}

static int __is_app_installed(char *pkgid, uid_t uid)
{
	pkgmgrinfo_pkginfo_h handle;
	int ret;
	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);

	if (ret < 0) {
		printf("package is not in pkgmgr_info DB\n");
		return -1;
	} else {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	return 0;
}

static void __print_usage()
{
	printf("\nPackage Manager Tool Version: %s\n\n", PKG_TOOL_VERSION);
	printf("-i, --install		install the package\n");
	printf("-u, --uninstall		uninstall the package\n");
	printf("-r, --reinstall		reinstall the package\n");
	printf("-w, --mount-install	mount install the package\n");
	printf("-c, --clear		clear user data\n");
	printf("-m, --move		move package\n");
	printf("-g, --getsize		get size of given package\n");
	printf("-T, --getsize-type	get type [0 : total size /1: data size]\n");
	printf("-l, --list		display list of installed packages available for the current user [i.e. User's specific Apps and Global Apps] \n");
	printf("-s, --show		show detail package info\n");
	printf("-a, --app-path		show app installation path\n");
	printf("-C, --check		check if applications belonging to a package are running or not\n");
	printf("-k, --kill		terminate applications belonging to a package\n");
	printf("-d, --descriptor	provide descriptor path\n");
	printf("-p, --package-path	provide package path\n");
	printf("-n, --package-name	provide package name\n");
	printf("-t, --package-type	provide package type\n");
	printf("-T, --move-type	provide move type [0 : move to internal /1: move to external]\n");
	printf("--global		Global Mode [Warning user should be privilegied to use this mode] \n");
	printf("-e, --tep-path provide TEP package path\n");
	printf("-M, --tep-move decide move/copy of TEP package[0:copy TEP package /1 : move TEP package, \n");
	printf("--add-blacklist         add a package to blacklist\n");
	printf("--remove-blacklist      remove a package from blacklist\n");
	printf("--check-blacklist       check if the given package is blacklisted\n");
	printf("-G, --debug-mode	install the package with debug mode for sdk\n");
	printf("-h, --help	.	print this help\n\n");

	printf("Usage: pkgcmd [options]\n");
	printf("pkgcmd -i -t <pkg type> (-d <descriptor path>) -p <pkg path> (--global)\n");
	printf("pkgcmd -u -n <pkgid> (--global)\n");
	printf("pkgcmd -r -t <pkg type> -n <pkgid> (--global) \n");
	printf("pkgcmd -w -t <pkg type> (-d <descriptor path>) -p <pkg path> (--global)\n");
	printf("pkgcmd -l (-t <pkg type>) \n");
	printf("pkgcmd -s -t <pkg type> -p <pkg path>\n");
	printf("pkgcmd -s -t <pkg type> -n <pkg name>\n");
	printf("pkgcmd -m -t <pkg type> -T <move type> -n <pkg name>\n\n");
	printf("pkgcmd -g -T <getsize type> -n <pkgid> \n");
	printf("pkgcmd -C -n <pkgid> \n");
	printf("pkgcmd -k -n <pkgid> \n");
	printf("pkgcmd -X <old_pkg> -Y <new_pkg> -Z <delta_pkg> \n");

	printf("Example:\n");
	printf("pkgcmd -u -n org.example.hello\n");
	printf("pkgcmd -i -t tpk -p /tmp/org.example.hello-1.0.0-arm.tpk\n");
	printf("pkgcmd -r -t tpk -n org.example.hello\n");
	printf("pkgcmd -w -t tpk -p /tmp/org.example.hello-1.0.0-arm.tpk\n");
	printf("pkgcmd -c -t tpk -n org.example.hello\n");
	printf("pkgcmd -m -t tpk -T 1 -n org.example.hello\n");
	printf("pkgcmd -C -n org.example.hello\n");
	printf("pkgcmd -k -n org.example.hello\n");
	printf("pkgcmd -a\n");
	printf("pkgcmd -a -t tpk -n org.example.hello\n");
	printf("pkgcmd -l\n");
	printf("pkgcmd -l -t tpk\n");
	printf("pkgcmd -g -T 0 -n org.example.hello\n");

	exit(0);

}

static int __pkgmgr_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *pkg_type = NULL;
	char *pkg_version = NULL;
	char *pkg_label = NULL;
	bool for_all_users = 0;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret == -1) {
		printf("Failed to get pkgmgrinfo_pkginfo_get_pkgid\n");
		return ret;
	}
	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkg_type);
	if (ret == -1) {
		printf("Failed to get pkgmgrinfo_pkginfo_get_type\n");
		return ret;
	}
	ret = pkgmgrinfo_pkginfo_get_version(handle, &pkg_version);
	if (ret == -1) {
		printf("Failed to get pkgmgrinfo_pkginfo_get_version\n");
		return ret;
	}
	ret = pkgmgrinfo_pkginfo_get_label(handle, &pkg_label);
	if (ret == -1)
		pkg_label = "(null)";

	ret = pkgmgrinfo_pkginfo_is_for_all_users(handle, &for_all_users);
	if (ret == -1) {
		printf("Failed to get pkgmgrinfo_pkginfo_is_for_all_users\n");
		return ret;
	}

	printf("%s\tpkg_type [%s]\tpkgid [%s]\tname [%s]\tversion [%s]\n",
			for_all_users ? "system apps" : "user apps ", pkg_type, pkgid, pkg_label, pkg_version);
	return ret;
}

static int __pkg_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid;
	pkgmgrinfo_uidinfo_t *uid_info = (pkgmgrinfo_uidinfo_t *) handle;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret < 0)
		printf("pkgmgrinfo_pkginfo_get_pkgid() failed\n");

	if (uid_info->uid != GLOBAL_USER)
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_GET_SIZE, PM_GET_TOTAL_SIZE,
				(pkgmgr_client *)user_data, NULL, pkgid, uid_info->uid, NULL, NULL, NULL);
	else
		ret = pkgmgr_client_request_service(PM_REQUEST_GET_SIZE, PM_GET_TOTAL_SIZE,
				(pkgmgr_client *)user_data, NULL, pkgid, NULL, NULL, NULL);
	if (ret < 0) {
		printf("pkgmgr_client_request_service Failed\n");
		return -1;
	}

	printf("pkg[%s] size = %d\n", pkgid, ret);

	return 0;
}

static int __process_request(uid_t uid)
{
	int ret = -1;
	pkgmgr_client *pc = NULL;
	char buf[1024] = {'\0'};
	int pid = -1;
	char pkg_old[PATH_MAX] = {0, };
	char pkg_new[PATH_MAX] = {0, };
	bool blacklist;

#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init();
#endif
	switch (data.request) {
	case INSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_path[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERRCODE_INVALID_VALUE;
			break;
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		if (data.tep_path[0] != '\0')
			pkgmgr_client_set_tep_path(pc, data.tep_path, data.tep_move);

		if (data.des_path[0] == '\0')
			ret = pkgmgr_client_usr_install(pc, data.pkg_type, NULL,
					data.pkg_path, NULL, PM_QUIET,
					__return_cb, pc, uid);
		else
			ret = pkgmgr_client_usr_install(pc, data.pkg_type,
					data.des_path, data.pkg_path,
					NULL, PM_QUIET, __return_cb, pc, uid);

		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERRCODE_PACKAGE_NOT_FOUND;
			break;
		}
		g_main_loop_run(main_loop);
		ret = data.result;
		break;
	case CREATE_DELTA:
		printf("CREATE_DELTA\n");
		if (data.pkg_old[0] == '\0' || data.pkg_new[0] == '\0') {
			printf("tpk pkg missing\n");
			break;
		}
		if (data.delta_pkg[0] == '\0') {
			snprintf(data.resolved_path_delta_pkg, PATH_MAX, "/tmp/delta_pkg");
			printf("output file will be /tmp/delta_pkg.delta\n");
		}
		const char *unzip_argv[] = {"sh", "/etc/package-manager/pkgmgr-unzip-pkg.sh", "-a",
				data.resolved_path_pkg_old, "-b", data.resolved_path_pkg_new, "-p",
				data.resolved_path_delta_pkg, NULL};
		ret = __xsystem(unzip_argv);
		if (ret != 0) {
			printf("unzip is fail .\n");
			return ret;
		}
		printf("unzip is success .\n");
		char *ptr_old_pkg = NULL;
		ptr_old_pkg = strrchr(data.resolved_path_pkg_old, '/');
		if (!ptr_old_pkg) {
			printf("not able to extract package name.\n");
			break;
		}
		ptr_old_pkg++;
		char *ptr_new_pkg = NULL;
		ptr_new_pkg = strrchr(data.resolved_path_pkg_new, '/');
		if (!ptr_new_pkg) {
			printf("not able to extract package name.\n");
			break;
		}
		ptr_new_pkg++;

		snprintf(pkg_old, PATH_MAX, "%s%s%s", TEMP_DELTA_REPO, ptr_old_pkg, UNZIPFILE);
		snprintf(pkg_new, PATH_MAX, "%s%s%s", TEMP_DELTA_REPO, ptr_new_pkg, UNZIPFILE);
		__create_diff_file(pkg_old, pkg_new);

		const char *delta_argv[] = {"sh", "/etc/package-manager/pkgmgr-create-delta.sh", "-a",
				data.resolved_path_pkg_old, "-b", data.resolved_path_pkg_new, "-p",
				data.resolved_path_delta_pkg, NULL};
		ret = __xsystem(delta_argv);
		if (ret != 0) {
			printf("create delta script fail .\n");
			return ret;
		}
		printf("create delta script success .\n");
		break;
	case UNINSTALL_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERRCODE_INVALID_VALUE;
			break;
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		ret = __is_app_installed(data.pkgid, uid);
		if (ret == -1) {
			printf("package is not installed\n");
			break;
		}

		ret = pkgmgr_client_usr_uninstall(pc, data.pkg_type, data.pkgid,
				PM_QUIET, __return_cb, NULL, uid);
		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERRCODE_PACKAGE_NOT_FOUND;
			break;
		}
		g_main_loop_run(main_loop);
		ret = data.result;
		break;

	case REINSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERRCODE_INVALID_VALUE;
			break;
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		ret = pkgmgr_client_usr_reinstall(pc, data.pkg_type, data.pkgid, NULL, PM_QUIET, __return_cb, pc, uid);
		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERRCODE_PACKAGE_NOT_FOUND;
			break;
		}
		g_main_loop_run(main_loop);
		ret = data.result;
		break;
	case MOUNT_INSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_path[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERRCODE_INVALID_VALUE;
			break;
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		if (data.tep_path[0] != '\0')
			pkgmgr_client_set_tep_path(pc, data.tep_path, data.tep_move);

		if (data.des_path[0] == '\0')
			ret = pkgmgr_client_usr_mount_install(pc, data.pkg_type, NULL,
					data.pkg_path, NULL, PM_QUIET,
					__return_cb, pc, uid);
		else
			ret = pkgmgr_client_usr_mount_install(pc, data.pkg_type,
					data.des_path, data.pkg_path,
					NULL, PM_QUIET, __return_cb, pc, uid);

		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERRCODE_PACKAGE_NOT_FOUND;
			break;
		}
		g_main_loop_run(main_loop);
		ret = data.result;
		break;
	case CLEAR_REQ:
		if (data.pkg_type[0] == '\0' || data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}
		ret = __is_app_installed(data.pkgid, uid);
		if (ret == -1) {
			printf("package is not installed\n");
			break;
		}
		ret = pkgmgr_client_usr_clear_user_data(pc, data.pkg_type,
				data.pkgid, PM_QUIET, uid);
		if (ret < 0)
			break;
		ret = data.result;
		break;

	case ACTIVATE_REQ:
		if (data.pkg_type[0] == '\0' || data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}

		if (strcmp(data.pkg_type, "app") == 0) {
			if (data.global)
				/* enable global app for this user only */
				ret = pkgmgr_client_activate_global_app_for_uid(pc, data.pkgid, __app_return_cb, getuid());
			else if (strlen(data.label) == 0)
				/* enable app which belongs to this user */
				ret = pkgmgr_client_usr_activate_app(pc, data.pkgid, __app_return_cb, uid);
			else {
				/* deprecated? */
				printf("label [%s]\n", data.label);
				char *largv[3] = {NULL, };
				largv[0] = "-l";
				largv[1] = data.label;
				ret = pkgmgr_client_usr_activate_appv(pc, data.pkgid, largv, uid);
			}
		} else
			/* enable package which belongs to this user */
			ret = pkgmgr_client_usr_activate(pc, data.pkg_type, data.pkgid, uid);

		if (ret < 0)
			break;

		g_main_loop_run(main_loop);
		ret = data.result;
		break;

	case DEACTIVATE_REQ:
		if (data.pkg_type[0] == '\0' || data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}

		if (strcmp(data.pkg_type, "app") == 0) {
			if (data.global)
				/* disable global app for this user only*/
				ret = pkgmgr_client_deactivate_global_app_for_uid(pc, data.pkgid, __app_return_cb, getuid());
			else
				/* disable app which belongs to this user */
				ret = pkgmgr_client_usr_deactivate_app(pc, data.pkgid, __app_return_cb, uid);
		} else
			/* disable package which belongs to this user*/
			ret = pkgmgr_client_usr_deactivate(pc, data.pkg_type, data.pkgid, uid);

		if (ret < 0)
			break;

		g_main_loop_run(main_loop);
		ret = data.result;

		break;

	case MOVE_REQ:
		if (data.pkg_type[0] == '\0' || data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}
		if (data.type < 0 || data.type > 1) {
			printf("Invalid move type...See usage\n");
			ret = -1;
			break;
		}
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}
		ret = __is_app_installed(data.pkgid, uid);
		if (ret == -1) {
			printf("package is not installed\n");
			break;
		}
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_MOVE, data.type, pc,
				data.pkg_type, data.pkgid, uid, NULL, NULL, NULL);

		printf("pkg[%s] move result = %d\n", data.pkgid, ret);

		if (ret < 0)
			break;
		ret = data.result;
		break;

	case APPPATH_REQ:
		if (data.pkg_type[0] == '\0' && data.pkgid[0] == '\0') {
			printf("Tizen Application Installation Path: %s\n", APP_INSTALLATION_PATH_RW);
			ret = 0;
			break;
		}
		if ((data.pkg_type[0] == '\0') || (data.pkgid[0] == '\0')) {
			printf("Use -h option to see usage\n");
			ret = -1;
			break;
		}
		if (strncmp(data.pkg_type, "wgt", PKG_TYPE_STRING_LEN_MAX - 1) == 0) {
			snprintf(buf, 1023, "%s/%s/res/wgt", APP_INSTALLATION_PATH_RW, data.pkgid);
			printf("Tizen Application Installation Path: %s\n", buf);
			ret = 0;
			break;
		} else if (strncmp(data.pkg_type, "tpk", PKG_TYPE_STRING_LEN_MAX - 1) == 0) {
			snprintf(buf, 1023, "%s/%s", APP_INSTALLATION_PATH_RW, data.pkgid);
			printf("Tizen Application Installation Path: %s\n", buf);
			ret = 0;
			break;
		} else {
			printf("Invalid package type.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}
		break;

	case KILLAPP_REQ:
	case CHECKAPP_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERRCODE_INVALID_VALUE;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		if (data.request == KILLAPP_REQ) {
			ret = pkgmgr_client_usr_request_service(PM_REQUEST_KILL_APP, 0, pc, NULL, data.pkgid, uid, NULL, NULL, &pid);
			if (ret < 0) {
				data.result = PKGCMD_ERRCODE_ERROR;
				break;
			}
			if (pid)
				printf("Pkgid: %s is Terminated\n", data.pkgid);
			else
				printf("Pkgid: %s is already Terminated\n", data.pkgid);

		} else if (data.request == CHECKAPP_REQ) {
			ret = pkgmgr_client_usr_request_service(PM_REQUEST_CHECK_APP, 0, pc, NULL, data.pkgid, uid, NULL, NULL, &pid);
			if (ret < 0) {
				data.result = PKGCMD_ERRCODE_ERROR;
				break;
			}

			if (pid)
				printf("Pkgid: %s is Running\n", data.pkgid);
			else
				printf("Pkgid: %s is Not Running\n", data.pkgid);
		}
		ret = data.result;
		break;

	case LIST_REQ:
		if (data.pkg_type[0] == '\0') {
			ret = 0;
			if (uid != GLOBAL_USER)
				ret = pkgmgrinfo_pkginfo_get_usr_list(__pkgmgr_list_cb, NULL, uid);
			else
				ret = pkgmgrinfo_pkginfo_get_list(__pkgmgr_list_cb, NULL);

			if (ret == -1)
				printf("no packages found\n");
			break;
		} else {
			pkgmgrinfo_pkginfo_filter_h handle;

			ret = pkgmgrinfo_pkginfo_filter_create(&handle);
			if (ret == -1) {
				printf("Failed to get package filter handle\n");
				break;
			}

			ret = pkgmgrinfo_pkginfo_filter_add_string(handle, PMINFO_PKGINFO_PROP_PACKAGE_TYPE, data.pkg_type);
			if (ret == -1) {
				printf("Failed to add package type filter\n");
				pkgmgrinfo_pkginfo_filter_destroy(handle);
				break;
			}

			if (uid != GLOBAL_USER)
				ret = pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(handle, __pkgmgr_list_cb, NULL, uid);
			else
				ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkgmgr_list_cb, NULL);

			if (ret != PMINFO_R_OK)
				printf("no package filter list\n");

			pkgmgrinfo_pkginfo_filter_destroy(handle);
			break;
		}

	case SHOW_REQ:
		/* unsupported */
		ret = -1;
		break;

	case CSC_REQ:
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_CSC, 0, NULL, NULL, NULL, uid,
				data.des_path, NULL, (void *)data.pkg_path);
		if (ret < 0)
			data.result = PKGCMD_ERRCODE_ERROR;
		break;

	case GETSIZE_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		if (data.type == 9) {
			ret = pkgmgrinfo_pkginfo_get_usr_list(__pkg_list_cb, (void *)pc, uid);
			break;
		}
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_GET_SIZE, data.type,
				pc, NULL, data.pkgid, uid, NULL, NULL, NULL);
		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		printf("pkg[%s] size = %d\n", data.pkgid, ret);
		ret = data.result;
		break;

	case HELP_REQ:
		__print_usage();
		ret = 0;
		break;

	case ADD_BLACKLIST_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		ret = pkgmgr_client_usr_add_blacklist(pc, data.pkgid, uid);
		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		printf("%d\n", ret);
		ret = data.result;
		break;
	case REMOVE_BLACKLIST_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		ret = pkgmgr_client_usr_remove_blacklist(pc, data.pkgid, uid);
		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		printf("%d\n", ret);
		ret = data.result;
		break;
	case CHECK_BLACKLIST_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			ret = -1;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		ret = pkgmgr_client_usr_check_blacklist(pc, data.pkgid, &blacklist, uid);
		if (ret < 0) {
			data.result = PKGCMD_ERRCODE_ERROR;
			break;
		}

		if (blacklist)
			printf("%s is blacklisted\n", data.pkgid);
		else
			printf("%s is not blacklisted\n", data.pkgid);

		ret = data.result;
		break;

	default:
		printf("Wrong Request\n");
		ret = -1;
		break;
	}

	if (pc) {
		pkgmgr_client_free(pc);
		pc = NULL;
	}
	return ret;
}

int main(int argc, char *argv[])
{
	optind = 1;
	int opt_idx = 0;
	int c = -1;
	int ret = -1;
	char *errstr = NULL;
	long starttime;
	long endtime;
	struct timeval tv;
	bool is_root_cmd = false;

	if (argc == 1)
		__print_usage();

	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	data.request = -1;
	memset(data.des_path, '\0', PATH_MAX);
	memset(data.pkg_path, '\0', PATH_MAX);
	memset(data.pkgid, '\0', PKG_NAME_STRING_LEN_MAX);
	memset(data.pkg_old, '\0', PATH_MAX);
	memset(data.pkg_new, '\0', PATH_MAX);
	memset(data.delta_pkg, '\0', PATH_MAX);
	memset(data.resolved_path_pkg_old, '\0', PATH_MAX);
	memset(data.resolved_path_pkg_new, '\0', PATH_MAX);
	memset(data.resolved_path_delta_pkg, '\0', PATH_MAX);
	memset(data.pkg_type, '\0', PKG_TYPE_STRING_LEN_MAX);
	memset(data.label, '\0', PKG_TYPE_STRING_LEN_MAX);
	memset(data.tep_path, '\0', PATH_MAX);
	memset(data.tep_move, '\0', PKG_NAME_STRING_LEN_MAX);

	data.global = 0; /* By default pkg_cmd will manage for the current user */
	data.result = 0;
	data.type = -1;
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options,
				&opt_idx);
		if (c == -1)
			break;	/* Parse end */
		switch (c) {
		case OPTVAL_GLOBAL:  /* global mode */
			data.global = 1;
			break;

		case 'i':  /* install */
			data.request = INSTALL_REQ;
			break;

		case 'u':  /* uninstall */
			data.request = UNINSTALL_REQ;
			break;

		case 'r':  /* reinstall */
			data.request = REINSTALL_REQ;
			break;

		case 'w':  /* mount install */
			data.request = MOUNT_INSTALL_REQ;
			break;

		case 'c':  /* clear */
			data.request = CLEAR_REQ;
			break;

		case 'g':  /* get pkg size */
			data.request = GETSIZE_REQ;
			break;

		case 'm':  /* move */
			data.request = MOVE_REQ;
			break;

		case 'S':  /* csc packages */
			data.request = CSC_REQ;
			if (optarg)
				snprintf(data.des_path, sizeof(data.des_path),
						"%s", optarg);
			printf("csc file is %s\n", data.des_path);
			break;

		case 'A':  /* activate */
			data.request = ACTIVATE_REQ;
			break;

		case 'D':  /* deactivate */
			data.request = DEACTIVATE_REQ;
			break;

		case 'L':  /* activate with Label */
			data.request = ACTIVATE_REQ;
			if (optarg)
				snprintf(data.pkg_path, sizeof(data.pkg_path),
						"%s", optarg);
			break;

		case 'a':  /* app installation path */
			data.request = APPPATH_REQ;
			break;

		case 'k':  /* Terminate applications of a package */
			data.request = KILLAPP_REQ;
			break;

		case 'C':  /* Check running status of applications of a package */
			data.request = CHECKAPP_REQ;
			break;

		case 'l':  /* list */
			data.request = LIST_REQ;
			break;

		case 's':  /* show */
			data.request = SHOW_REQ;
			break;

		case 'p':  /* package path */
			if (optarg)
				snprintf(data.pkg_path, sizeof(data.pkg_path),
						"%s", optarg);
			ret = __convert_to_absolute_path(data.pkg_path);
			if (ret == -1) {
				printf("conversion of relative path to absolute path failed\n");
				return -1;
			}
			printf("path is %s\n", data.pkg_path);
			break;

		case 'X':  /* old_tpk */
			data.request = CREATE_DELTA;
			is_root_cmd = true;
			if (optarg)
				strncpy(data.pkg_old, optarg, PATH_MAX - 1);

			if (realpath(data.pkg_old, data.resolved_path_pkg_old) == NULL) {
				printf("failed to set realpath\n");
				return -1;
			}
			printf("pkg_old abs path is %s\n", data.resolved_path_pkg_old);
			break;

		case 'Y':  /* new_tpk */
			if (optarg)
				strncpy(data.pkg_new, optarg, PATH_MAX - 1);

			if (realpath(data.pkg_new, data.resolved_path_pkg_new) == NULL) {
				printf("failed to set realpath\n");
				return -1;
			}
			printf("pkg_new abs path is %s\n", data.resolved_path_pkg_new);
			break;

		case 'Z':  /* delta_tpk */
			if (optarg)
				strncpy(data.delta_pkg, optarg, PATH_MAX - 1);

			printf("delta_pkg is %s\n", data.delta_pkg);
			if (realpath(data.delta_pkg, data.resolved_path_delta_pkg) == NULL) {
				printf("failed to set realpath\n");
				return -1;
			}
			printf("delta_pkg abs path is %s\n", data.resolved_path_delta_pkg);
			break;
		case 'd':  /* descriptor path */
			if (optarg)
				snprintf(data.des_path, sizeof(data.des_path),
						"%s", optarg);
			break;

		case 'n':  /* package name */
			if (optarg)
				snprintf(data.pkgid, sizeof(data.pkgid),
						"%s", optarg);
			break;

		case 'e':  /* tep name */
			if (optarg)
				strncpy(data.tep_path, optarg,
					PATH_MAX - 1);
			ret = __convert_to_absolute_tep_path(data.tep_path);
			if (ret == -1) {
				printf("conversion of relative tep path to absolute path failed\n");
				return -1;
			}
			printf("TEP path is %s\n", data.tep_path);
			break;

		case 'M':  /*tep move*/
			if (optarg)
				strncpy(data.tep_move, (atoi(optarg) == 1) ? "tep_move" : "tep_copy",
						PKG_NAME_STRING_LEN_MAX - 1);
			break;

		case 't':  /* package type */
			if (optarg)
				snprintf(data.pkg_type, sizeof(data.pkg_type),
						"%s", optarg);
			break;

		case 'T':  /* move type */
			data.type = atoi(optarg);
			break;

		case 'h':  /* help */
			data.request = HELP_REQ;
			break;

		case 'q':  /* quiet mode is removed */
			break;

		case 'G':  /* debug mode */
			break;

		case OPTVAL_ADD_BLACKLIST:
			data.request = ADD_BLACKLIST_REQ;
			if (optarg)
				snprintf(data.pkgid, sizeof(data.pkgid),
						"%s", optarg);
			break;

		case OPTVAL_REMOVE_BLACKLIST:
			data.request = REMOVE_BLACKLIST_REQ;
			if (optarg)
				snprintf(data.pkgid, sizeof(data.pkgid),
						"%s", optarg);
			break;

		case OPTVAL_CHECK_BLACKLIST:
			data.request = CHECK_BLACKLIST_REQ;
			if (optarg)
				snprintf(data.pkgid, sizeof(data.pkgid),
						"%s", optarg);
			break;

			/* Otherwise */
		case '?':  /* Not an option */
			__print_usage();
			break;

		case ':':  /* */
			break;

		default:
			break;

		}
	}

	uid_t uid = getuid();
	if (!is_root_cmd && uid == OWNER_ROOT) {
		printf("Current User is Root! : Only regular users are allowed\n");
		return -1;
	}

	if (data.global == 1)
		uid = GLOBAL_USER;

	ret = __process_request(uid);
	if ((ret < 0) && (data.result == 0)) {
		printf("Undefined error(%d)", ret);
		data.result = PKGCMD_ERRCODE_UNDEFINED_ERROR;
	}

	if (ret != 0) {
		__error_no_to_string(data.result, &errstr);
		printf("processing result : %s [%d] failed\n", errstr, data.result);
	}

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;
	printf("spend time for pkgcmd is [%d]ms\n", (int)(endtime - starttime));

	return data.result;
}
