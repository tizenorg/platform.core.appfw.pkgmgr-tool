
/*
 * slp-pkgmgr
 *
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

#define PKG_TOOL_VERSION	"0.1"
#define APP_INSTALLATION_PATH_RW	tzplatform_getenv(TZ_USER_APP)
#define MAX_QUERY_LEN	4096

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
//tmp
#define PKG_PATH_STRING_LEN_MAX 512

static int __process_request(uid_t uid);
static void __print_usage();
static int __is_app_installed(char *pkgid, uid_t uid);
static int __return_cb(uid_t target_uid, int req_id, const char *pkg_type,
		       const char *pkgid, const char *key, const char *val,
		       const void *pmsg, void *data);
static int __convert_to_absolute_path(char *path);

/* Supported options */
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
const char *short_options = "iurmcgCkaADL:lsd:p:t:n:T:S:e:M:Gqh";
const struct option long_options[] = {
	{"install", 0, NULL, 'i'},
	{"uninstall", 0, NULL, 'u'},
	{"reinstall", 0, NULL, 'r'},
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
	{"package-type", 1, NULL, 't'},
	{"package-name", 1, NULL, 'n'},
	{"move-type", 1, NULL, 'T'},
	{"getsize-type", 1, NULL, 'T'},
	{"csc", 1, NULL, 'S'},
	{"tep-path", 1, NULL, 'e'},
	{"tep-move", 1, NULL, 'M'},
	{"global", 0, NULL, 'G'},
	{"quiet", 0, NULL, 'q'},
	{"help", 0, NULL, 'h'},
	{0, 0, 0, 0}		/* sentinel */
};
#else
const char *short_options = "iurmcgCkaADL:lsd:p:t:n:T:S:Gqh";
const struct option long_options[] = {
	{"install", 0, NULL, 'i'},
	{"uninstall", 0, NULL, 'u'},
	{"reinstall", 0, NULL, 'r'},
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
	{"package-type", 1, NULL, 't'},
	{"package-name", 1, NULL, 'n'},
	{"move-type", 1, NULL, 'T'},
	{"getsize-type", 1, NULL, 'T'},
	{"csc", 1, NULL, 'S'},
	{"global", 0, NULL, 'G'},
	{"quiet", 0, NULL, 'q'},
	{"help", 0, NULL, 'h'},
	{0, 0, 0, 0}		/* sentinel */
};
#endif

enum pm_tool_request_e {
	INSTALL_REQ = 1,
	UNINSTALL_REQ,
	REINSTALL_REQ,
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
	HELP_REQ
};
typedef enum pm_tool_request_e req_type;

struct pm_tool_args_t {
	req_type request;
	char pkg_path[PKG_PATH_STRING_LEN_MAX];
	char pkg_type[PKG_TYPE_STRING_LEN_MAX];
	char pkgid[PKG_NAME_STRING_LEN_MAX];
	char des_path[PKG_PATH_STRING_LEN_MAX];
	char label[PKG_NAME_STRING_LEN_MAX];
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	char tep_path[PKG_PATH_STRING_LEN_MAX];
	char tep_move[PKG_NAME_STRING_LEN_MAX];
#endif
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
	case PKGCMD_ERR_PACKAGE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_PACKAGE_INVALID:
		*errstr = PKGCMD_ERR_PACKAGE_INVALID_STR;
		break;
	case PKGCMD_ERR_PACKAGE_LOWER_VERSION:
		*errstr = PKGCMD_ERR_PACKAGE_LOWER_VERSION_STR;
		break;
	case PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_MANIFEST_INVALID:
		*errstr = PKGCMD_ERR_MANIFEST_INVALID_STR;
		break;
	case PKGCMD_ERR_CONFIG_NOT_FOUND:
		*errstr = PKGCMD_ERR_CONFIG_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CONFIG_INVALID:
		*errstr = PKGCMD_ERR_CONFIG_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_NOT_FOUND:
		*errstr = PKGCMD_ERR_SIGNATURE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_INVALID:
		*errstr = PKGCMD_ERR_SIGNATURE_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND:
		*errstr = PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_INVALID:
		*errstr = PKGCMD_ERR_CERTIFICATE_INVALID_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_EXPIRED:
		*errstr = PKGCMD_ERR_CERTIFICATE_EXPIRED_STR;
		break;
	case PKGCMD_ERR_INVALID_PRIVILEGE:
		*errstr = PKGCMD_ERR_INVALID_PRIVILEGE_STR;
		break;
	case PKGCMD_ERR_MENU_ICON_NOT_FOUND:
		*errstr = PKGCMD_ERR_MENU_ICON_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_FATAL_ERROR:
		*errstr = PKGCMD_ERR_FATAL_ERROR_STR;
		break;
	case PKGCMD_ERR_OUT_OF_STORAGE:
		*errstr = PKGCMD_ERR_OUT_OF_STORAGE_STR;
		break;
	case PKGCMD_ERR_OUT_OF_MEMORY:
		*errstr = PKGCMD_ERR_OUT_OF_MEMORY_STR;
		break;
	case PKGCMD_ERR_ARGUMENT_INVALID:
		*errstr = PKGCMD_ERR_ARGUMENT_INVALID_STR;
		break;
	default:
		*errstr = PKGCMD_ERR_UNKNOWN_STR;
		break;
	}
}

static int __return_cb(uid_t target_uid, int req_id, const char *pkg_type,
		       const char *pkgid, const char *key, const char *val,
		       const void *pmsg, void *priv_data)
{
	int ret_val;
	char delims[] = ":";
	char *extra_str = NULL;
	char *ret_result = NULL;

	if (strncmp(key, "error", strlen("error")) == 0) {
		ret_val = atoi(val);
		data.result = ret_val;

		ret_result = strstr((char *)val, delims);
		if (ret_result){
			extra_str = strdup(ret_result);
			printf("__return_cb req_id[%d] pkg_type[%s] pkgid[%s] key[%s] val[%d] error message: %s\n",
					   req_id, pkg_type, pkgid, key, ret_val, extra_str);
			free(extra_str);
		}
		else
			printf("__return_cb req_id[%d] pkg_type[%s] pkgid[%s] key[%s] val[%d]\n",
					   req_id, pkg_type, pkgid, key, ret_val);
	} else
		printf("__return_cb req_id[%d] pkg_type[%s] "
			   "pkgid[%s] key[%s] val[%s]\n",
			   req_id, pkg_type, pkgid, key, val);

	if (strncmp(key, "end", strlen("end")) == 0) {
		if ((strncmp(val, "fail", strlen("fail")) == 0) && data.result == 0){
			data.result = PKGCMD_ERR_FATAL_ERROR;
		}
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

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
static int __convert_to_absolute_tep_path(char *path)
{
	char abs[PKG_PATH_STRING_LEN_MAX] = {'\0'};
	char temp[PKG_PATH_STRING_LEN_MAX] = {'\0'};
	char *ptr = NULL;
	if (path == NULL) {
		printf("path is NULL\n");
		return -1;
	}
	strncpy(temp, path, PKG_PATH_STRING_LEN_MAX - 1);
	if (strchr(path, '/') == NULL) {
		getcwd(abs, PKG_PATH_STRING_LEN_MAX - 1);
		if (abs[0] == '\0') {
			printf("getcwd() failed\n");
			return -1;
		}
		memset(data.tep_path, '\0', PKG_PATH_STRING_LEN_MAX);
		snprintf(data.tep_path, PKG_PATH_STRING_LEN_MAX - 1, "%s/%s", abs, temp);
		return 0;
	}
	if (strncmp(path, "./", 2) == 0) {
		ptr = temp;
		getcwd(abs, PKG_PATH_STRING_LEN_MAX - 1);
		if (abs[0] == '\0') {
			printf("getcwd() failed\n");
			return -1;
		}
		ptr = ptr + 2;
		memset(data.tep_path, '\0', PKG_PATH_STRING_LEN_MAX);
		snprintf(data.tep_path, PKG_PATH_STRING_LEN_MAX - 1, "%s/%s", abs, ptr);
		return 0;
	}
	return 0;
}
#endif

static int __is_app_installed(char *pkgid, uid_t uid)
{
	pkgmgrinfo_pkginfo_h handle;
	int ret;
	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);

	if(ret < 0) {
		printf("package is not in pkgmgr_info DB\n");
		return -1;
	} else
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

static void __print_usage()
{
	printf("\nPackage Manager Tool Version: %s\n\n", PKG_TOOL_VERSION);
	printf("-i, --install		install the package\n");
	printf("-u, --uninstall		uninstall the package\n");
	printf("-r, --reinstall		reinstall the package\n");
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
	printf("-G, --global	Global Mode [Warning user should be privilegied to use this mode] \n");
#if 1//#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	printf("-e, --tep-path provide TEP package path\n");
	printf("-M, --tep-move decide move/copy of TEP package[0:copy TEP package /1 : move TEP package, \n");
#endif
	printf("-h, --help	.	print this help\n\n");

	printf("Usage: pkgcmd [options]\n");
	printf("pkgcmd -i -t <pkg type> (-d <descriptor path>) -p <pkg path> (-G)\n");
	printf("pkgcmd -u -n <pkgid> (-G)\n");
	printf("pkgcmd -r -t <pkg type> -n <pkgid> (-G) \n");
	printf("pkgcmd -l (-t <pkg type>) \n");
	printf("pkgcmd -s -t <pkg type> -p <pkg path>\n");
	printf("pkgcmd -s -t <pkg type> -n <pkg name>\n");
	printf("pkgcmd -m -t <pkg type> -T <move type> -n <pkg name>\n\n");
	printf("pkgcmd -g -T <getsize type> -n <pkgid> \n");
	printf("pkgcmd -C -n <pkgid> \n");
	printf("pkgcmd -k -n <pkgid> \n");

	printf("Example:\n");
	printf("pkgcmd -u -n com.samsung.calculator\n");
	printf("pkgcmd -i -t rpm -p /mnt/nfs/com.samsung.calculator_0.1.2-95_armel.rpm\n");
	printf("pkgcmd -r -t rpm -n com.samsung.calculator\n");
	printf("pkgcmd -c -t rpm -n com.samsung.hello\n");
	printf("pkgcmd -m -t rpm -T 1 -n com.samsung.hello\n");
	printf("pkgcmd -C -n com.samsung.hello\n");
	printf("pkgcmd -k -n com.samsung.hello\n");
	printf("pkgcmd -a\n");
	printf("pkgcmd -a -t rpm -n com.samsung.hello\n");
	printf("pkgcmd -l\n");
	printf("pkgcmd -l -t tpk\n");
	printf("pkgcmd -g -T 0 -n com.samsung.calculator\n");

	exit(0);

}

static int __pkgmgr_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
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

	printf("%s\tpkg_type [%s]\tpkgid [%s]\tname [%s]\tversion [%s]\n", for_all_users ? "system apps" : "user apps ", pkg_type, pkgid, pkg_label, pkg_version);
	return ret;
}

static int __pkg_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid;
	pkgmgrinfo_uidinfo_t *uid_info = (pkgmgrinfo_uidinfo_t *) handle;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		printf("pkgmgrinfo_pkginfo_get_pkgid() failed\n");
	}
  if (uid_info->uid != GLOBAL_USER)
	  ret = pkgmgr_client_usr_request_service(PM_REQUEST_GET_SIZE, PM_GET_TOTAL_SIZE, (pkgmgr_client *)user_data, NULL, pkgid, uid_info->uid, NULL, NULL, NULL);
  else
	  ret = pkgmgr_client_request_service(PM_REQUEST_GET_SIZE, PM_GET_TOTAL_SIZE, (pkgmgr_client *)user_data, NULL, pkgid, NULL, NULL, NULL);
	if (ret < 0){
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
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif
	switch (data.request) {
	case INSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkg_path[0] == '\0') {
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
			if (data.tep_path[0] == '\0') {
				printf("Please provide the arguments.\n");
				printf("use -h option to see usage\n");
				data.result = PKGCMD_ERR_ARGUMENT_INVALID;
				break;
			} else
				printf("only TEP installation\n");
#else
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERR_ARGUMENT_INVALID;
			break;
#endif
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERR_FATAL_ERROR;
			break;
		}
		if (data.des_path[0] == '\0') {
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
			if (data.tep_path[0] != '\0')
				pkgmgr_client_set_tep_path(pc, data.tep_path, data.tep_move);
#endif
			ret =
				pkgmgr_client_usr_install(pc, data.pkg_type, NULL,
						data.pkg_path, NULL, PM_QUIET,
						__return_cb, pc, uid);
		}else{
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
			if (data.tep_path[0] != '\0')
				pkgmgr_client_set_tep_path(pc, data.tep_path, data.tep_move);
#endif
			ret =
				pkgmgr_client_usr_install(pc, data.pkg_type,
						data.des_path, data.pkg_path,
						NULL, PM_QUIET, __return_cb, pc, uid);

		}
		if (ret < 0){
			data.result = PKGCMD_ERR_FATAL_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERR_PACKAGE_NOT_FOUND;
			break;
		}
		g_main_loop_run(main_loop);
		ret = data.result;
		break;

	case UNINSTALL_REQ:
		if (data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERR_ARGUMENT_INVALID;
			break;
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERR_FATAL_ERROR;
			break;
		}
//if global
		ret = __is_app_installed(data.pkgid, uid);
		if (ret == -1) {
			printf("package is not installed\n");
			break;
		}

		ret =
		    pkgmgr_client_usr_uninstall(pc, data.pkg_type, data.pkgid,
					    PM_QUIET, __return_cb, NULL,uid);
		if (ret < 0){
			data.result = PKGCMD_ERR_FATAL_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERR_PACKAGE_NOT_FOUND;
			break;
		}
		g_main_loop_run(main_loop);
		ret = data.result;
		break;

	case REINSTALL_REQ:
		if (data.pkg_type[0] == '\0' || data.pkgid[0] == '\0') {
			printf("Please provide the arguments.\n");
			printf("use -h option to see usage\n");
			data.result = PKGCMD_ERR_ARGUMENT_INVALID;
			break;
		}
		main_loop = g_main_loop_new(NULL, FALSE);
		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERR_FATAL_ERROR;
			break;
		}

		ret = pkgmgr_client_usr_reinstall(pc, data.pkg_type, data.pkgid, NULL, PM_QUIET, __return_cb, pc, uid);
		if (ret < 0){
			data.result = PKGCMD_ERR_FATAL_ERROR;
			if (access(data.pkg_path, F_OK) != 0)
				data.result = PKGCMD_ERR_PACKAGE_NOT_FOUND;
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

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			ret = -1;
			break;
		}

		if ( strcmp(data.pkg_type, "app") == 0 ) {
			if (strlen(data.label) == 0) {
				ret = pkgmgr_client_usr_activate_app(pc, data.pkgid, uid);
				if (ret < 0)
					break;
			} else {
				printf("label [%s]\n", data.label);
				char *largv[3] = {NULL, };
				largv[0] = "-l";
				largv[1] = data.label;
				ret = pkgmgr_client_usr_activate_appv(pc, data.pkgid, largv, uid);
				if (ret < 0)
					break;
			}
		} else {
				ret = pkgmgr_client_usr_activate(pc, data.pkg_type, data.pkgid, uid);
				if (ret < 0)
					break;
		}
		ret = data.result;

		break;


	case DEACTIVATE_REQ:
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

		if ( strcmp(data.pkg_type, "app") == 0 ) {
			ret = pkgmgr_client_usr_deactivate_app(pc, data.pkgid, uid);
			if (ret < 0)
				break;
		}else {
			ret = pkgmgr_client_usr_deactivate(pc, data.pkg_type, data.pkgid, uid);
			if (ret < 0)
				break;
		}
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
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_MOVE, data.type, pc, NULL, data.pkgid, uid, NULL, NULL, NULL);

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
		if (strncmp(data.pkg_type, "rpm", PKG_TYPE_STRING_LEN_MAX - 1) == 0) {
			snprintf(buf, 1023, "%s/%s", APP_INSTALLATION_PATH_RW, data.pkgid);
			printf("Tizen Application Installation Path: %s\n", buf);
			ret = 0;
			break;
		} else if (strncmp(data.pkg_type, "wgt", PKG_TYPE_STRING_LEN_MAX - 1) == 0) {
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
			data.result = PKGCMD_ERR_ARGUMENT_INVALID;
			break;
		}

		pc = pkgmgr_client_new(PC_REQUEST);
		if (pc == NULL) {
			printf("PkgMgr Client Creation Failed\n");
			data.result = PKGCMD_ERR_FATAL_ERROR;
			break;
		}

		if (data.request == KILLAPP_REQ) {
			ret = pkgmgr_client_usr_request_service(PM_REQUEST_KILL_APP, 0, pc, NULL, data.pkgid, uid, NULL, NULL, &pid);
			if (ret < 0){
				data.result = PKGCMD_ERR_FATAL_ERROR;
				break;
			}
			if (pid)
				printf("Pkgid: %s is Terminated\n", data.pkgid);
			else
				printf("Pkgid: %s is already Terminated\n", data.pkgid);

		} else if (data.request == CHECKAPP_REQ) {
			ret = pkgmgr_client_usr_request_service(PM_REQUEST_CHECK_APP, 0, pc, NULL, data.pkgid, uid, NULL, NULL, &pid);
			if (ret < 0){
				data.result = PKGCMD_ERR_FATAL_ERROR;
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
			if (uid != GLOBAL_USER) {
				ret = pkgmgrinfo_pkginfo_get_usr_list(__pkgmgr_list_cb, NULL, uid);
			} else {
				ret = pkgmgrinfo_pkginfo_get_list(__pkgmgr_list_cb, NULL);
				}
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
			if (uid != GLOBAL_USER) {
				ret = pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(handle, __pkgmgr_list_cb, NULL, uid);
			} else {
				ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkgmgr_list_cb, NULL);
			}
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
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_CSC, 0, NULL, NULL, NULL, uid, data.des_path, NULL, (void *)data.pkg_path);
		if (ret < 0)
			data.result = PKGCMD_ERR_FATAL_ERROR;
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
			data.result = PKGCMD_ERR_FATAL_ERROR;
			break;
		}

		if (data.type == 9) {
			ret = pkgmgrinfo_pkginfo_get_usr_list(__pkg_list_cb, (void *)pc, uid);
			break;
		}
		ret = pkgmgr_client_usr_request_service(PM_REQUEST_GET_SIZE, data.type, pc, NULL, data.pkgid, uid, NULL, NULL, NULL);
		if (ret < 0){
			data.result = PKGCMD_ERR_FATAL_ERROR;
			break;
		}

		printf("pkg[%s] size = %d\n", data.pkgid, ret);
		ret = data.result;
		break;

	case HELP_REQ:
		__print_usage();
		ret = 0;
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


	if (argc == 1)
		__print_usage();

	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	data.request = -1;
	memset(data.des_path, '\0', PKG_PATH_STRING_LEN_MAX);
	memset(data.pkg_path, '\0', PKG_PATH_STRING_LEN_MAX);
	memset(data.pkgid, '\0', PKG_NAME_STRING_LEN_MAX);
	memset(data.pkg_type, '\0', PKG_TYPE_STRING_LEN_MAX);
	memset(data.label, '\0', PKG_TYPE_STRING_LEN_MAX);
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	memset(data.tep_path, '\0', PKG_PATH_STRING_LEN_MAX);
	memset(data.tep_move, '\0', PKG_NAME_STRING_LEN_MAX);
#endif
	data.global = 0; //By default pkg_cmd will manage for the current user
	data.result = 0;
	data.type = -1;
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options,
				&opt_idx);
		if (c == -1)
			break;	/* Parse end */
		switch (c) {
		case 'G':	/* install */
			data.global = 1;
			break;

		case 'i':	/* install */
			data.request = INSTALL_REQ;
			break;

		case 'u':	/* uninstall */
			data.request = UNINSTALL_REQ;
			break;

		case 'r':	/* reinstall */
			data.request = REINSTALL_REQ;
			break;

		case 'c':	/* clear */
			data.request = CLEAR_REQ;
			break;

		case 'g':	/* get pkg size */
			data.request = GETSIZE_REQ;
			break;

		case 'm':	/* move */
			data.request = MOVE_REQ;
			break;

		case 'S': /* csc packages */
			data.request = CSC_REQ;
			if (optarg)
				snprintf(data.des_path, sizeof(data.des_path),
						"%s", optarg);
			printf("csc file is %s\n", data.des_path);
			break;

		case 'A':	/* activate */
			data.request = ACTIVATE_REQ;
			break;

		case 'D':	/* deactivate */
			data.request = DEACTIVATE_REQ;
			break;

		case 'L':	/* activate with Label */
			data.request = ACTIVATE_REQ;
			if (optarg)
				snprintf(data.pkg_path, sizeof(data.pkg_path),
						"%s", optarg);
			break;

		case 'a':	/* app installation path */
			data.request = APPPATH_REQ;
			break;

		case 'k':	/* Terminate applications of a package */
			data.request = KILLAPP_REQ;
			break;

		case 'C':	/* Check running status of applications of a package */
			data.request = CHECKAPP_REQ;
			break;

		case 'l':	/* list */
			data.request = LIST_REQ;
			break;

		case 's':	/* show */
			data.request = SHOW_REQ;
			break;

		case 'p':	/* package path */
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

		case 'd':	/* descriptor path */
			if (optarg)
				snprintf(data.des_path, sizeof(data.des_path),
						"%s", optarg);
			break;

		case 'n':	/* package name */
			if (optarg)
				snprintf(data.pkgid, sizeof(data.pkgid),
						"%s", optarg);
			break;
 #ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		case 'e':	/* tep name */
			if (optarg)
				strncpy(data.tep_path, optarg,
					PKG_PATH_STRING_LEN_MAX - 1);
			ret = __convert_to_absolute_tep_path(data.tep_path);
			if (ret == -1) {
				printf("conversion of relative tep path to absolute path failed\n");
				return -1;
			}
			printf("TEP path is %s\n", data.tep_path);
			break;
		case 'M': /*tep move*/
			if (optarg)
				strncpy(data.tep_move, (atoi(optarg) == 1)?"tep_move":"tep_copy", PKG_NAME_STRING_LEN_MAX - 1);
			break;
#endif
		case 't':	/* package type */
			if (optarg)
				snprintf(data.pkg_type, sizeof(data.pkg_type),
						"%s", optarg);
			break;

		case 'T':	/* move type */
			data.type = atoi(optarg);
			break;

		case 'h':	/* help */
			data.request = HELP_REQ;
			break;

		case 'q':	/* quiet mode is removed */
			break;

			/* Otherwise */
		case '?':	/* Not an option */
			__print_usage();
			break;

		case ':':	/* */
			break;

		default:
			break;

		}
	}
	uid_t uid = getuid();
	if(uid == OWNER_ROOT) {
		printf("Current User is Root! : Only regular users are allowed\n");
		return -1;
	}
	if(data.global == 1) {
		uid = GLOBAL_USER;
	}
	ret = __process_request(uid);
	if ((ret == -1) && (data.result != 0))
		data.result = PKGCMD_ERR_ARGUMENT_INVALID;

	if (ret != 0) {
		__error_no_to_string(data.result, &errstr);
		printf("processing result : %s [%d] failed\n", errstr, data.result);
	}

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;
	printf("spend time for pkgcmd is [%d]ms\n", (int)(endtime - starttime));

	return data.result;
}
