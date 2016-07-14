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
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>

#include <package-manager.h>
#include <package-manager-types.h>
#include <pkgmgr_installer.h>

#define OWNER_ROOT 0

static void __print_usage();
static int __get_pkg_info(char *pkgid, uid_t uid);
static int __get_app_info(char *appid);
static int __get_app_list(char *pkgid, uid_t uid);
static int __get_app_category_list(char *appid);
static int __get_app_metadata_list(char *appid);
static int __get_app_control_list(char *appid);
static int __get_pkg_list(uid_t uid);
static int __get_installed_app_list(uid_t uid);
static int __add_app_filter(uid_t uid);
static int __add_pkg_filter(uid_t uid);
static int __set_certinfo_in_db(char *pkgid, uid_t uid);
static int __get_certinfo_from_db(char *pkgid, uid_t uid);
static int __del_certinfo_from_db(char *pkgid);
static int __get_integer_input_data(void);
char *__get_string_input_data(void);
static int __pkg_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data);
static int __app_category_list_cb(const char *category_name, void *user_data);
static int __app_control_list_cb(const char *operation, const char *uri, const char *mime, void *user_data);
static int __app_metadata_list_cb(const char *metadata_name, const char *metadata_value, void *user_data);
int app_func(const pkgmgrinfo_appinfo_h handle, void *user_data);

static void __get_pkgmgrinfo_pkginfo(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *type = NULL;
	char *version = NULL;
	char *author_name = NULL;
	char *author_email = NULL;
	char *author_href = NULL;
	char *root_path = NULL;
	char *mainappid = NULL;
	pkgmgrinfo_install_location location = 0;
	char *icon = NULL;
	char *label = NULL;
	char *desc = NULL;
	bool removable = 0;
	bool preload = 0;
	bool readonly = 0;
	bool update = 0;
	bool system = 0;
	int installed_time = -1;

	ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
	if (ret < 0)
		printf("Failed to get pkg type\n");
	if (type)
		printf("Type: %s\n", type);

	ret = pkgmgrinfo_pkginfo_get_version(handle, &version);
	if (ret < 0)
		printf("Failed to get version\n");
	if (version)
		printf("Version: %s\n", version);

	ret = pkgmgrinfo_pkginfo_get_install_location(handle, &location);
	if (ret < 0)
		printf("Failed to get install location\n");
	printf("Install Location: %d\n", location);

	ret = pkgmgrinfo_pkginfo_get_icon(handle, &icon);
	if (ret < 0)
		printf("Failed to get icon\n");
	if (icon)
		printf("Icon: %s\n", icon);

	ret = pkgmgrinfo_pkginfo_get_label(handle, &label);
	if (ret < 0)
		printf("Failed to get label\n");
	if (label)
		printf("Label: %s\n", label);

	ret = pkgmgrinfo_pkginfo_get_description(handle, &desc);
	if (ret < 0)
		printf("Failed to get description\n");
	if (desc)
		printf("Description: %s\n", desc);

	ret = pkgmgrinfo_pkginfo_get_author_name(handle, &author_name);
	if (ret < 0)
		printf("Failed to get author name\n");
	if (author_name)
		printf("Author Name: %s\n", author_name);

	ret = pkgmgrinfo_pkginfo_get_author_email(handle, &author_email);
	if (ret < 0)
		printf("Failed to get author email\n");
	if (author_email)
		printf("Author Email: %s\n", author_email);

	ret = pkgmgrinfo_pkginfo_get_author_href(handle, &author_href);
	if (ret < 0)
		printf("Failed to get author href\n");
	if (author_href)
		printf("Author Href: %s\n", author_href);

	ret = pkgmgrinfo_pkginfo_get_root_path(handle, &root_path);
	if (ret < 0)
		printf("Failed to get root_path\n");
	if (root_path)
		printf("root_path : %s\n", root_path);

	ret = pkgmgrinfo_pkginfo_get_mainappid(handle, &mainappid);
	if (ret < 0)
		printf("Failed to get mainappid\n");
	if (mainappid)
		printf("mainappid : %s\n", mainappid);

	ret = pkgmgrinfo_pkginfo_get_installed_time(handle, &installed_time);
	if (ret < 0)
		printf("Failed to get install time\n");
	printf("Install time: %d\n", installed_time);

	ret = pkgmgrinfo_pkginfo_is_removable(handle, &removable);
	if (ret < 0)
		printf("Failed to get removable\n");
	else
		printf("Removable: %d\n", removable);

	ret = pkgmgrinfo_pkginfo_is_preload(handle, &preload);
	if (ret < 0)
		printf("Failed to get preload\n");
	else
		printf("Preload: %d\n", preload);

	ret = pkgmgrinfo_pkginfo_is_readonly(handle, &readonly);
	if (ret < 0)
		printf("Failed to get readonly\n");
	else
		printf("Readonly: %d\n", readonly);

	ret = pkgmgrinfo_pkginfo_is_update(handle, &update);
	if (ret < 0)
		printf("Failed to get update\n");
	else
		printf("update: %d\n", update);

	ret = pkgmgrinfo_pkginfo_is_system(handle, &system);
	if (ret < 0)
		printf("Failed to get system\n");
	else
		printf("system: %d\n", system);
}

int __get_app_id(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	char *apptype = NULL;
	int ret = -1;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0)
		printf("Failed to get appid\n");

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret < 0)
		printf("Failed to get package\n");
	printf("apptype [%s]\t appid [%s]\n", apptype, appid);

	return 0;
}

static int __get_integer_input_data(void)
{
	char input_str[32] = { 0, };
	int data = 0;

	if (fgets(input_str, sizeof(input_str), stdin) == NULL) {
		printf("fgets() failed....\n");
		return -1;
	}

	if (sscanf(input_str, "%4d", &data) != 1) {
		printf("Input only integer option....\n");
		return -1;
	}

	return data;
}


char *__get_string_input_data(void)
{
	char *data = (char *)malloc(1024);
	if (data == NULL) {
		printf("Malloc Failed\n");
		return NULL;
	}

	if (fgets(data, 1024, stdin) == NULL) {
		printf("Buffer overflow!!! try again\n");
		exit(-1);
	}
	data[strlen(data) - 1] = '\0';

	return data;
}

static void __print_usage()
{
	printf("For Getting package|App Info\n");
	printf("\tpkginfo --[pkg|app] <pkgid|appid>\n\n");
	printf("For Getting list of installed packages\n");
	printf("\tpkginfo --listpkg \n\n");
	printf("For Getting list of installed applications\n");
	printf("\tpkginfo --listapp \n\n");
	printf("For Getting app list for a particular package\n");
	printf("\tpkginfo --list <pkgid>\n\n");
	printf("For Getting app category list for a particular application\n");
	printf("\tpkginfo --category <appid>\n\n");
	printf("For Getting app metadata  list for a particular application\n");
	printf("\tpkginfo --metadata <appid>\n\n");
	printf("For Getting app control list for a particular application\n");
	printf("\tpkginfo --appcontrol <appid>\n\n");
	printf("To insert|remove manifest info in DB\n");
	printf("\tpkginfo --[imd|rmd] <manifest file name>\n\n");
	printf("To set manifest validation\n");
	printf("\tpkginfo --check <manifest file name>\n\n");
	printf("To set cert info in DB\n");
	printf("\tpkginfo --setcert <pkgid>\n\n");
	printf("To get cert info from DB\n");
	printf("\tpkginfo --getcert <pkgid>\n\n");
	printf("To compare pkg cert info from DB\n");
	printf("\tpkginfo --cmp-pkgcert <lhs_pkgid> <rhs_pkgid>\n\n");
	printf("To compare app cert info from DB\n");
	printf("\tpkginfo --cmp-appcert <lhs_appid> <rhs_appid>\n\n");
	printf("To delete all cert info from DB\n");
	printf("\tpkginfo --delcert <pkgid>\n\n");
	printf("To add application filter values [Multiple values can be added]\n");
	printf("\tpkginfo --app-flt\n\n");
	printf("To add package filter values [Multiple values can be added]\n");
	printf("\tpkginfo --pkg-flt\n\n");
	printf("To add metadata filter values\n");
	printf("\tpkginfo --metadata-flt\n\n");
}

static void __print_arg_filter_usage()
{
	printf("=========================================\n");
	printf("pkginfo --arg-flt key value\n");
	printf("ex : pkginfo --arg-flt 6 webapp\n");
	printf("key list is bellowed\n");
	printf("2  --> filter by app ID\n");
	printf("3  --> filter by app component\n");
	printf("4  --> filter by app exec\n");
	printf("5  --> filter by app icon\n");
	printf("6  --> filter by app type\n");
	printf("7  --> filter by app operation\n");
	printf("8  --> filter by app uri\n");
	printf("9  --> filter by app mime\n");
	printf("10 --> filter by app category\n");
	printf("11 --> filter by app nodisplay [0|1]\n");
	printf("12 --> filter by app multiple [0|1]\n");
	printf("13 --> filter by app onboot [0|1]\n");
	printf("14 --> filter by app autorestart [0|1]\n");
	printf("15 --> filter by app taskmanage [0|1]\n");
	printf("16 --> filter by app hwacceleration\n");
	printf("17 --> filter by app screenreader\n");
	printf("=========================================\n");
}

static int __app_list_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);
	printf("appid : %s\n", appid);

	return 0;
}

static int __add_metadata_filter()
{
	int ret = 0;
	pkgmgrinfo_appinfo_metadata_filter_h handle;
	char *key = NULL;
	char *value = NULL;

	ret = pkgmgrinfo_appinfo_metadata_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_metadata_filter_create() failed\n");
		return ret;
	}

	printf("enter metadata - key\n");
	key = __get_string_input_data();
	printf("enter metadata - value\n");
	value = __get_string_input_data();

	printf("filter condition : key=[%s], value=[%s]\n", key, value);

	ret = pkgmgrinfo_appinfo_metadata_filter_add(handle, key, value);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_metadata_filter_add() failed\n");
		goto err;
	}

	ret = pkgmgrinfo_appinfo_metadata_filter_foreach(handle, __app_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_metadata_filter_add() failed\n");
		goto err;
	}

err:
	pkgmgrinfo_appinfo_metadata_filter_destroy(handle);
	if (key) {
		free(key);
		key = NULL;
	}
	if (value) {
		free(value);
		value = NULL;
	}
	return ret;
}

static int __add_app_filter(uid_t uid)
{
	int ret = 0;
	int choice = -1;
	char *value = NULL;
	int val = -1;
	int count = 0;
	pkgmgrinfo_appinfo_filter_h handle;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret > 0) {
		printf("appinfo filter handle create failed\n");
		return -1;
	}

	while (choice != 0 && choice != 1) {
		printf("Enter Choice\n");
		printf("0  --> Finalize filter and get count of apps\n");
		printf("1  --> Finalize filter and get list of apps\n");
		printf("2  --> filter by app ID\n");
		printf("3  --> filter by app component\n");
		printf("4  --> filter by app exec\n");
		printf("5  --> filter by app icon\n");
		printf("6  --> filter by app type\n");
		printf("7  --> filter by app operation\n");
		printf("8  --> filter by app uri\n");
		printf("9  --> filter by app mime\n");
		printf("10 --> filter by app category\n");
		printf("11 --> filter by app nodisplay [0|1]\n");
		printf("12 --> filter by app multiple [0|1]\n");
		printf("13 --> filter by app onboot [0|1]\n");
		printf("14 --> filter by app autorestart [0|1]\n");
		printf("15 --> filter by app taskmanage [0|1]\n");
		printf("16 --> filter by app hwacceleration\n");
		printf("17 --> filter by app screenreader\n");
		printf("18 --> filter by app ui-gadget [0|1]\n");
		printf("19 --> filter by app support disable [0|1]\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			ret = pkgmgrinfo_appinfo_filter_count(handle, &count);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_count() failed\n");
				ret = -1;
				goto err;
			}
			printf("App count = %d\n", count);
			break;
		case 1:
			if (uid != GLOBAL_USER)
				ret = pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle, app_func, NULL, uid);
			else
				ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, app_func, NULL);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_foreach_appinfo() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 2:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_ID, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 3:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_COMPONENT, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 4:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_EXEC, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 5:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_ICON, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 6:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_TYPE, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 7:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_OPERATION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 8:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_URI, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 9:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_MIME, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 10:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_CATEGORY, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 11:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_NODISPLAY, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 12:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_MULTIPLE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 13:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_ONBOOT, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 14:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_AUTORESTART, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 15:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
				PMINFO_APPINFO_PROP_APP_TASKMANAGE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 16:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_HWACCELERATION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 17:
			value = __get_string_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_SCREENREADER, value);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 18:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
					PMINFO_APPINFO_PROP_APP_UI_GADGET, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 19:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_appinfo_filter_add_bool(handle,
					PMINFO_APPINFO_PROP_APP_SUPPORT_DISABLE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		default:
			printf("Invalid filter property\n");
			ret = -1;
			goto err;
		}
	}
	ret = 0;
err:
	pkgmgrinfo_appinfo_filter_destroy(handle);
	if (value) {
		free(value);
		value = NULL;
	}
	return ret;
}

static int __add_pkg_filter(uid_t uid)
{
	int ret = 0;
	int choice = -1;
	char *value = NULL;
	int val = -1;
	int count = 0;
	pkgmgrinfo_pkginfo_filter_h handle;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret > 0) {
		printf("pkginfo filter handle create failed\n");
		return -1;
	}

	while (choice != 0 && choice != 1) {
		printf("Enter Choice\n");
		printf("0  --> Finalize filter and get count of packages\n");
		printf("1  --> Finalize filter and get list of packages\n");
		printf("2  --> filter by package ID\n");
		printf("3  --> filter by package version\n");
		printf("4  --> filter by package type\n");
		printf("5  --> filter by package install location\n");
		printf("6  --> filter by author name\n");
		printf("7  --> filter by author email\n");
		printf("8  --> filter by author href\n");
		printf("9  --> filter by package removable [0|1]\n");
		printf("10 --> filter by package readonly [0|1]\n");
		printf("11 --> filter by package preload [0|1]\n");
		printf("12 --> filter by package update [0|1]\n");
		printf("13 --> filter by package appsetting [0|1]\n");
		printf("14 --> filter by package installed storage[installed_internal | installed_external]\n");
		printf("15 --> filter by package privilege\n");
		printf("16 --> filter by package support disable [0|1]\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			if (uid != GLOBAL_USER)
				ret = pkgmgrinfo_pkginfo_usr_filter_count(handle, &count, uid);
			else
				ret = pkgmgrinfo_pkginfo_filter_count(handle, &count);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_count() failed\n");
				ret = -1;
				goto err;
			}
			printf("Package count = %d\n", count);
			break;
		case 1:
			if (uid != GLOBAL_USER)
				ret = pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(handle, __pkg_list_cb, NULL, uid);
			else
				ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkg_list_cb, NULL);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_(usr)_filter_foreach_pkginfo() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 2:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_ID, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 3:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_VERSION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 4:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_TYPE, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 5:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 6:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 7:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 8:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 9:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 10:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_READONLY, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 11:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 12:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_UPDATE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 13:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_APPSETTING, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		case 14:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_INSTALLED_STORAGE, value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 15:
			value = __get_string_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_string(handle,
					PMINFO_PKGINFO_PROP_PACKAGE_PRIVILEGE,
					value);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 16:
			val = __get_integer_input_data();
			ret = pkgmgrinfo_pkginfo_filter_add_bool(handle,
				PMINFO_PKGINFO_PROP_PACKAGE_SUPPORT_DISABLE, val);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
				ret = -1;
				goto err;
			}
			break;
		default:
			printf("Invalid filter property\n");
			ret = -1;
			goto err;
		}
	}
	ret = 0;
err:
	pkgmgrinfo_pkginfo_filter_destroy(handle);
	if (value) {
		free(value);
		value = NULL;
	}
	return ret;
}

static int __add_arg_filter(char *key, char *value, uid_t uid)
{
	int ret = 0;
	int choice = -1;
	int val = -1;
	pkgmgrinfo_appinfo_filter_h handle;
	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret > 0) {
		printf("appinfo filter handle create failed\n");
		return -1;
	}
	choice = atoi(key);

	switch (choice) {
	case 2:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_ID, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 3:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_COMPONENT, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 4:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_EXEC, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 5:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_ICON, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 6:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_TYPE, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 7:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_OPERATION, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 8:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_URI, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 9:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_MIME, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		free(value);
		value = NULL;
		break;
	case 10:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_CATEGORY, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_string() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 11:
		val = atoi(value);
		ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_NODISPLAY, val);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 12:
		val = atoi(value);
		ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_MULTIPLE, val);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 13:
		val = atoi(value);
		ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_ONBOOT, val);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 14:
		val = atoi(value);
		ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_AUTORESTART, val);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 15:
		val = atoi(value);
		ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_TASKMANAGE, val);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 16:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_HWACCELERATION, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;
	case 17:
		ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_SCREENREADER, value);
		if (ret < 0) {
			printf("pkgmgrinfo_appinfo_filter_add_bool() failed\n");
			ret = -1;
			goto err;
		}
		break;

	default:
		__print_arg_filter_usage();
		goto err;
	}
	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle, __get_app_id, NULL, uid);
	else
		ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, __get_app_id, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_filter_foreach_appinfo() failed\n");
		ret = -1;
		goto err;
	}

err:
	pkgmgrinfo_appinfo_filter_destroy(handle);
	return ret;
}
static int __del_certinfo_from_db(char *pkgid)
{
	int ret = 0;
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	ret = pkgmgr_installer_delete_certinfo(pkgid);
	if (ret < 0) {
		printf("pkgmgr_installer_delete_certinfo failed\n");
		return -1;
	}
	return 0;
}

static int __get_certinfo_from_db(char *pkgid, uid_t uid)
{
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	int ret = 0;
	int choice = -1;
	int i = 0;
	const char *value = NULL;
	pkgmgrinfo_certinfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_create_certinfo(&handle);
	if (ret < 0) {
		printf("pkgmgrinfo_pkginfo_create_certinfo failed\n");
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle, uid);
	if (ret < 0) {
		printf("pkgmgrinfo_pkginfo_load_certinfo failed\n");
		return -1;
	}

	while (choice != 10) {
		printf("Enter the choice to get\n");
		printf("0 --> to get all cert values\n");
		printf("1 --> author root certificate\n");
		printf("2 --> author intermediate certificate\n");
		printf("3 --> author signer certificate\n");
		printf("4 --> distributor root certificate\n");
		printf("5 --> distributor intermediate certificate\n");
		printf("6 --> distributor signer certificate\n");
		printf("7 --> distributor2 root certificate\n");
		printf("8 --> distributor2 intermediate certificate\n");
		printf("9 --> distributor2 signer certificate\n");
		printf("10 --> exit\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			for (i = 0; i < 9; i++) {
				pkgmgrinfo_pkginfo_get_cert_value(handle, i, &value);
				if (value)
					printf("cert type[%d] value = %s\n", i, value);
			}
			break;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			ret = pkgmgrinfo_pkginfo_get_cert_value(handle, choice - 1, &value);
			if (value)
				printf("cert type[%d] value = %s\n", choice - 1, value);
			if (ret < 0)
				ret = -1;
			break;
		case 10:
			ret = pkgmgrinfo_pkginfo_destroy_certinfo(handle);
			if (ret < 0) {
				printf("pkgmgrinfo_pkginfo_destroy_certinfo failed\n");
				ret = -1;
			}
			break;
		default:
			printf("Invalid choice entered\n");
			ret = -1;
			break;
		}
	}

	return ret;
}

static int __compare_pkg_certinfo_from_db(char *lhs_pkgid, char *rhs_pkgid, uid_t uid)
{
	if (lhs_pkgid == NULL || rhs_pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}

	int ret = 0;
	pkgmgrinfo_cert_compare_result_type_e result;
	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(lhs_pkgid, rhs_pkgid, uid, &result);
	else
		ret = pkgmgrinfo_pkginfo_compare_pkg_cert_info(lhs_pkgid, rhs_pkgid, &result);
	if (ret != PMINFO_R_OK)
		return -1;

	printf("Compare [match=0, mismatch=1, lhs_no=2, rhs_no=3, both_no=4]\n");
	printf("pkgid =[%s] and [%s] compare result = [%d] \n", lhs_pkgid, rhs_pkgid, result);
	return 0;
}

static int __compare_app_certinfo_from_db(char *lhs_appid, char *rhs_appid, uid_t uid)
{
	if (lhs_appid == NULL || rhs_appid == NULL) {
		printf("appid is NULL\n");
		return -1;
	}

	int ret = 0;
	pkgmgrinfo_cert_compare_result_type_e result;
	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_compare_usr_app_cert_info(lhs_appid, rhs_appid, uid, &result);
	else
		ret = pkgmgrinfo_pkginfo_compare_app_cert_info(lhs_appid, rhs_appid, &result);
	if (ret != PMINFO_R_OK)
		return -1;

	printf("Compare [match=0, mismatch=1, lhs_no=2, rhs_no=3, both_no=4]\n");
	printf("appid =[%s] and [%s] compare result = [%d] \n", lhs_appid, rhs_appid, result);
	return 0;
}

static int __set_certinfo_in_db(char *pkgid, uid_t uid)
{
	if (pkgid == NULL) {
		printf("pkgid is NULL\n");
		return -1;
	}
	int ret = 0;
	int choice = -1;
	char *value = NULL;
	pkgmgr_instcertinfo_h handle = NULL;

	ret = pkgmgr_installer_create_certinfo_set_handle(&handle);
	if (ret < 0) {
		printf("pkgmgr_installer_create_certinfo_set_handle failed\n");
		return -1;
	}

	while (choice != 0) {
		printf("Enter the choice you want to set\n");
		printf("0 --> to set data in DB\n");
		printf("1 --> author root certificate\n");
		printf("2 --> author intermediate certificate\n");
		printf("3 --> author signer certificate\n");
		printf("4 --> distributor root certificate\n");
		printf("5 --> distributor intermediate certificate\n");
		printf("6 --> distributor signer certificate\n");
		printf("7 --> distributor2 root certificate\n");
		printf("8 --> distributor2 intermediate certificate\n");
		printf("9 --> distributor2 signer certificate\n");
		choice = __get_integer_input_data();
		switch (choice) {
		case 0:
			ret = pkgmgr_installer_save_certinfo(pkgid, handle, uid);
			if (ret < 0) {
				printf("pkgmgr_installer_save_certinfo failed\n");
				pkgmgr_installer_destroy_certinfo_set_handle(handle);
				return -1;
			}
			ret = pkgmgr_installer_destroy_certinfo_set_handle(handle);
			if (ret < 0) {
				printf("pkgmgr_installer_destroy_certinfo_set_handle failed\n");
				return -1;
			}
			return 0;
		case 1:
			printf("Enter Author Root Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 0, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 2:
			printf("Enter Author Intermediate Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 1, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 3:
			printf("Enter Author Signer Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 2, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 4:
			printf("Enter Distributor Root Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 3, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 5:
			printf("Enter Distributor Intermediate Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 4, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 6:
			printf("Enter Distributor Signer Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 5, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 7:
			printf("Enter Distributor2 Root Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 6, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 8:
			printf("Enter Distributor2 Intermediate Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 7, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		case 9:
			printf("Enter Distributor2 Signer Certificate Value: \n");
			value = __get_string_input_data();
			ret = pkgmgr_installer_set_cert_value(handle, 8, value);
			if (ret < 0) {
				printf("pkgmgr_installer_set_cert_value failed\n");
				ret = -1;
				goto err;
			}
			free(value);
			value = NULL;
			break;
		default:
			printf("Invalid Number Entered\n");
			choice = 0;
			ret = pkgmgr_installer_destroy_certinfo_set_handle(handle);
			if (ret < 0) {
				printf("pkgmgr_installer_destroy_certinfo_set_handle failed\n");
				return -1;
			}
			break;
		}
	}
err:
	if (value) {
		free(value);
		value = NULL;
	}
	pkgmgr_installer_destroy_certinfo_set_handle(handle);
	return ret;
}

int app_func(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = -1;
	char *appid;
	char *data = NULL;
	char *exec = NULL;
	char *icon = NULL;
	char *label = NULL;
	char *apptype = NULL;
	char *package = NULL;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	bool onboot = 0;
	bool autorestart = 0;
	pkgmgrinfo_app_component component = 0;
	pkgmgrinfo_app_hwacceleration hwacceleration;
	pkgmgrinfo_app_screenreader screenreader;

	if (user_data)
		data = (char *)user_data;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0)
		printf("Failed to get appid\n");
	if (appid)
		printf("Appid: %s\n", appid);

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &package);
	if (ret < 0)
		printf("Failed to get package\n");
	if (package)
		printf("Package: %s\n", package);

	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret < 0)
		printf("Failed to get exec\n");
	if (exec)
		printf("Exec: %s\n", exec);

	ret = pkgmgrinfo_appinfo_get_icon(handle, &icon);
	if (ret < 0)
		printf("Failed to get icon\n");
	if (icon)
		printf("Icon: %s\n", icon);

	ret = pkgmgrinfo_appinfo_get_label(handle, &label);
	if (ret < 0)
		printf("Failed to get label\n");
	if (label)
		printf("Label: %s\n", label);

	ret = pkgmgrinfo_appinfo_get_component(handle, &component);
	if (ret < 0)
		printf("Failed to get component\n");

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret < 0)
		printf("Failed to get apptype\n");
	if (apptype)
		printf("Apptype: %s\n", apptype);

	if (component == PMINFO_UI_APP || component == PMINFO_WIDGET_APP ||
		component == PMINFO_WATCH_APP) {
		printf("component: %s\n", component == PMINFO_UI_APP ?
			"uiapp" : component == PMINFO_WIDGET_APP ?
			"widgetapp" : "watchapp");
		ret = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
		if (ret < 0)
			printf("Failed to get multiple\n");
		else
			printf("Multiple: %d\n", multiple);

		ret = pkgmgrinfo_appinfo_is_nodisplay(handle, &nodisplay);
		if (ret < 0)
			printf("Failed to get nodisplay\n");
		else
			printf("Nodisplay: %d \n", nodisplay);

		ret = pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage);
		if (ret < 0)
			printf("Failed to get taskmanage\n");
		else
			printf("Taskmanage: %d\n", taskmanage);

		ret = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacceleration);
		if (ret < 0)
			printf("Failed to get hwacceleration\n");
		else
			printf("hw-acceleration: %d\n", hwacceleration);

		ret = pkgmgrinfo_appinfo_get_screenreader(handle, &screenreader);
		if (ret < 0)
			printf("Failed to get screenreader\n");
		else
			printf("screenreader: %d\n", screenreader);
	}

	if (component == PMINFO_SVC_APP) {
		printf("component: svcapp\n");
		ret = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
		if (ret < 0)
			printf("Failed to get onboot\n");
		else
			printf("Onboot: %d\n", onboot);

		ret = pkgmgrinfo_appinfo_is_autorestart(handle, &autorestart);
		if (ret < 0)
			printf("Failed to get autorestart\n");
		else
			printf("Autorestart: %d \n", autorestart);
	}

	if (data)
		printf("user_data : %s\n\n", data);

	return 0;
}


static int __pkg_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	int installed_time = -1;
	char *test_data = "test data";
	char *pkgid;
	char *pkg_type;
	char *pkg_version;
	bool preload = 0;

	pkgmgrinfo_uidinfo_t *uid_info = (pkgmgrinfo_uidinfo_t *) handle;
	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret < 0)
		printf("pkgmgrinfo_pkginfo_get_pkgid() failed\n");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkg_type);
	if (ret < 0)
		printf("pkgmgrinfo_pkginfo_get_type() failed\n");

	ret = pkgmgrinfo_pkginfo_get_version(handle, &pkg_version);
	if (ret < 0)
		printf("pkgmgrinfo_pkginfo_get_version() failed\n");

	ret = pkgmgrinfo_pkginfo_is_preload(handle, &preload);
	if (ret < 0)
		printf("pkgmgrinfo_pkginfo_is_preload() failed\n");

	ret = pkgmgrinfo_pkginfo_get_installed_time(handle, &installed_time);
	if (ret < 0)
		printf("pkgmgrinfo_pkginfo_get_installed_time() failed\n");

	printf("---------------------------------------\n");
	printf("pkg_type [%s]\tpkgid [%s]\tversion [%s]\tpreload [%d]\tinstalled_time [%d]\n", pkg_type,
	       pkgid, pkg_version, preload, installed_time);

	if (uid_info->uid != GLOBAL_USER) {
		printf("**List of Ui-Apps**\n");
		ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_UI_APP, app_func, (void *)test_data, uid_info->uid);
		if (ret < 0)
			printf("pkgmgr_get_info_app() failed\n");

		printf("**List of Svc-Apps**\n");
		ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_SVC_APP, app_func, (void *)test_data, uid_info->uid);
		if (ret < 0)
			printf("pkgmgr_get_info_app() failed\n");
	} else {
		printf("**List of Ui-Apps**\n");
		ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, app_func, (void *)test_data);
		if (ret < 0)
			printf("pkgmgr_get_info_app() failed\n");

		printf("**List of Svc-Apps**\n");
		ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, app_func, (void *)test_data);
		if (ret < 0)
			printf("pkgmgr_get_info_app() failed\n");
	}
	printf("---------------------------------------\n");

	return 0;
}

static int __get_pkg_list(uid_t uid)
{
	int ret = -1;

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_list(__pkg_list_cb, NULL, uid);
	else
		ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_pkginfo_get_list() failed\n");
		return -1;
	}

	return 0;
}

static int __get_installed_app_list(uid_t uid)
{
	int ret = -1;

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_appinfo_get_usr_installed_list(app_func, uid, NULL);
	else
		ret = pkgmgrinfo_appinfo_get_installed_list(app_func, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_get_installed_list() failed\n");
		return -1;
	}

	return 0;
}


static int __app_category_list_cb(const char *category_name, void *user_data)
{
	if (category_name)
		printf("Category: %s\n", category_name);
	return 0;
}

static int __app_metadata_list_cb(const char *metadata_name, const char *metadata_value, void *user_data)
{
	if (metadata_name && metadata_value) {
		printf("Name: %s\n", metadata_name);
		printf("Value: %s\n",	metadata_value);
		printf("\n");
	}
	return 0;
}

static int __app_control_list_cb(const char *operation, const char *uri, const char *mime, void *user_data)
{
	printf("-------------------------------------------------------\n");
	printf("Operation: %s\n", operation);
	printf("Uri: %s\n", uri);
	printf("Mime: %s\n", mime);
	printf("-------------------------------------------------------\n\n");
	return 0;
}


static int __get_app_category_list(char *appid)
{
	int ret = -1;
	pkgmgrinfo_appinfo_h handle;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_foreach_category(handle, __app_category_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_foreach_category() failed\n");
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return -1;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return 0;
}

static int __get_app_metadata_list(char *appid)
{
	int ret = -1;
	pkgmgrinfo_appinfo_h handle;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_foreach_metadata(handle, __app_metadata_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_foreach_metadata() failed\n");
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return -1;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return 0;
}

static int __get_app_control_list(char *appid)
{
	int ret = -1;
	pkgmgrinfo_appinfo_h handle;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_foreach_appcontrol(handle, __app_control_list_cb, NULL);
	if (ret < 0) {
		printf("pkgmgrinfo_appinfo_foreach_appcontrol() failed\n");
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return -1;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return 0;
}

static int __get_app_list(char *pkgid, uid_t uid)
{
	int ret = -1;
	char *test_data = "test data";
	pkgmgrinfo_pkginfo_h handle;

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	if (uid != GLOBAL_USER) {
		printf("List of Ui-Apps\n\n");
		ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_UI_APP, app_func, (void *)test_data, uid);
		if (ret < 0)
			printf("pkgmgrinfo_appinfo_get_list() failed\n");

		printf("List of Svc-Apps\n\n");
		ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_SVC_APP, app_func, (void *)test_data, uid);
		if (ret < 0)
			printf("pkgmgrinfo_appinfo_get_list() failed\n");
	} else {
		printf("List of Ui-Apps\n\n");
		ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, app_func, (void *)test_data);
		if (ret < 0)
			printf("pkgmgrinfo_appinfo_get_list() failed\n");

		printf("List of Svc-Apps\n\n");
		ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, app_func, (void *)test_data);
		if (ret < 0)
			printf("pkgmgrinfo_appinfo_get_list() failed\n");
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

static int __get_pkg_info(char *pkgid, uid_t uid)
{
	int ret = -1;
	pkgmgrinfo_pkginfo_h handle;

	printf("Get Pkg Info Called [%s]\n", pkgid);
	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	__get_pkgmgrinfo_pkginfo(handle, NULL);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

static int __get_app_info(char *appid)
{
	int ret = -1;
	char *exec = NULL;
	char *app_id = NULL;
	char *apptype = NULL;
	char *icon = NULL;
	char *label = NULL;
	char *package = NULL;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	bool onboot = 0;
	bool autorestart = 0;
	bool enabled = 0;
	bool preload = 0;
	pkgmgrinfo_appinfo_h handle;
	pkgmgrinfo_app_component component = 0;
	pkgmgrinfo_app_hwacceleration hwacceleration;
	pkgmgrinfo_app_screenreader screenreader;

	printf("Get App Info Called [%s]\n", appid);

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &handle);
	if (ret < 0) {
		printf("Failed to get handle\n");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &package);
	if (ret < 0)
		printf("Failed to get package\n");

	ret = pkgmgrinfo_appinfo_get_appid(handle, &app_id);
	if (ret < 0)
		printf("Failed to get exec\n");

	ret = pkgmgrinfo_appinfo_get_label(handle, &label);
	if (ret < 0)
		printf("Failed to get label\n");

	ret = pkgmgrinfo_appinfo_get_icon(handle, &icon);
	if (ret < 0)
		printf("Failed to get icon\n");

	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret < 0)
		printf("Failed to get exec\n");

	ret = pkgmgrinfo_appinfo_get_component(handle, &component);
	if (ret < 0)
		printf("Failed to get component\n");

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret < 0)
		printf("Failed to get apptype\n");

	ret = pkgmgrinfo_appinfo_is_nodisplay(handle, &nodisplay);
	if (ret < 0)
		printf("Failed to get nodisplay\n");

	ret = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
	if (ret < 0)
		printf("Failed to get multiple\n");

	ret = pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage);
	if (ret < 0)
		printf("Failed to get taskmanage\n");

	ret = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacceleration);
	if (ret < 0)
		printf("Failed to get hwacceleration\n");

	ret = pkgmgrinfo_appinfo_get_screenreader(handle, &screenreader);
	if (ret < 0)
		printf("Failed to get screenreader\n");

	ret = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
	if (ret < 0)
		printf("Failed to get onboot\n");

	ret = pkgmgrinfo_appinfo_is_autorestart(handle, &autorestart);
	if (ret < 0)
		printf("Failed to get autorestart\n");

	ret = pkgmgrinfo_appinfo_is_enabled(handle, &enabled);
	if (ret < 0)
		printf("Failed to get enabled\n");

	ret = pkgmgrinfo_appinfo_is_preload(handle, &preload);
	if (ret < 0)
		printf("Failed to get preload\n");

	if (app_id)
		printf("Appid: %s\n", app_id);

	if (package)
		printf("Package: %s\n", package);

	if (exec)
		printf("Exec: %s\n", exec);

	if (apptype)
		printf("Apptype: %s\n", apptype);

	if (component == PMINFO_UI_APP || component == PMINFO_WIDGET_APP ||
		component == PMINFO_WATCH_APP) {
		printf("component: %s\n", component == PMINFO_UI_APP ?
			"uiapp" : component == PMINFO_WIDGET_APP ?
			"widgetapp": "watchapp");
		if (icon)
			printf("Icon: %s\n", icon);
		if (label)
			printf("Label: %s\n", label);
		printf("Nodisplay: %d\n", nodisplay);
		printf("Multiple: %d\n", multiple);
		printf("Taskmanage: %d\n", taskmanage);
		printf("Hw-Acceleration: %d\n", hwacceleration);
		printf("Screenreader: %d\n", screenreader);
	} else if (component == PMINFO_SVC_APP) {
		printf("component: svcapp\n");

		if (icon)
			printf("Icon: %s\n", icon);
		if (label)
			printf("Label: %s\n", label);

		printf("Autorestart: %d\n", autorestart);
		printf("Onboot: %d\n", onboot);
	} else {
		printf("Invalid Component Type\n");
	}

	printf("Enabled: %d\n", enabled);
	printf("Preload: %d\n", preload);

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return 0;
}

static int __check_manifest_validation(char *manifest)
{
	int ret = 0;

	if (manifest == NULL) {
		printf("Manifest file is NULL\n");
		return -1;
	}

	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret < 0) {
		printf("check manifest validation failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	long starttime;
	long endtime;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	if (argc == 2) {
		if (strcmp(argv[1], "--listpkg") == 0) {
			ret = __get_pkg_list(getuid());
			if (ret == -1) {
				printf("get pkg list failed\n");
				goto end;
			} else {
				goto end;
			}
		} else if (strcmp(argv[1], "--app-flt") == 0) {
			ret = __add_app_filter(getuid());
			if (ret == -1) {
				printf("Adding app filter failed\n");
				goto end;
			} else {
				goto end;
			}
		} else if (strcmp(argv[1], "--pkg-flt") == 0) {
			ret = __add_pkg_filter(getuid());
			if (ret == -1) {
				printf("Adding pkg filter failed\n");
				goto end;
			} else {
				goto end;
			}
		} else if (strcmp(argv[1], "--metadata-flt") == 0) {
			ret = __add_metadata_filter();
			if (ret == -1) {
				printf("Adding pkg filter failed\n");
				goto end;
			} else {
				goto end;
			}
		} else if (strcmp(argv[1], "--listapp") == 0) {
			ret = __get_installed_app_list(getuid());
			if (ret == -1) {
				printf("get installed app list failed\n");
				goto end;
			} else {
				goto end;
			}
		} else {
			__print_usage();
			ret = -1;
			goto end;
		}
	} else if (argc == 4) {
		if (strcmp(argv[1], "--cmp-pkgcert") == 0) {
			ret = __compare_pkg_certinfo_from_db(argv[2], argv[3], getuid());
			if (ret == -1) {
				printf("compare certinfo from db failed\n");
				goto end;
			}
			goto end;
		} else if (strcmp(argv[1], "--cmp-appcert") == 0) {
			ret = __compare_app_certinfo_from_db(argv[2], argv[3], getuid());
			if (ret == -1) {
				printf("compare certinfo from db failed\n");
				goto end;
			}
			goto end;
		} else if (strcmp(argv[1], "--arg-flt") == 0) {
			ret = __add_arg_filter(argv[2], argv[3], getuid());
			if (ret == -1) {
				printf("compare certinfo from db failed\n");
				goto end;
			}
			goto end;
		} else {
			__print_usage();
			ret = -1;
			goto end;
		}
	}

	if (argc != 3) {
		__print_usage();
		ret = -1;
		goto end;
	}
	if (!argv[1] || !argv[2]) {
			__print_usage();
			ret = -1;
			goto end;
	}

	if (strcmp(argv[1], "--pkg") == 0) {
		ret = __get_pkg_info(argv[2], getuid());
		if (ret == -1) {
			printf("get pkg info failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--app") == 0) {
		ret = __get_app_info(argv[2]);
		if (ret == -1) {
			printf("get app info failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--list") == 0) {
		ret = __get_app_list(argv[2], getuid());
		if (ret == -1) {
			printf("get app list failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--imd") == 0) {
		printf("Not supported!\n");
		goto end;
	} else if (strcmp(argv[1], "--fota") == 0) {
		printf("Not supported!\n");
		goto end;
	} else if (strcmp(argv[1], "--rmd") == 0) {
		printf("Not supported!\n");
		goto end;
	} else if (strcmp(argv[1], "--setcert") == 0) {
		ret = __set_certinfo_in_db(argv[2], getuid());
		if (ret == -1) {
			printf("set certinfo in db failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--getcert") == 0) {
		ret = __get_certinfo_from_db(argv[2], getuid());
		if (ret == -1) {
			printf("get certinfo from db failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--delcert") == 0) {
		ret = __del_certinfo_from_db(argv[2]);
		if (ret == -1) {
			printf("del certinfo from db failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--check") == 0) {
		ret = __check_manifest_validation(argv[2]);
		if (ret == -1) {
			printf("check manifest failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--category") == 0) {
		ret = __get_app_category_list(argv[2]);
		if (ret == -1) {
			printf("get app category list failed\n");
			goto end;
		}
	} else if (strcmp(argv[1], "--metadata") == 0) {
		ret = __get_app_metadata_list(argv[2]);
		if (ret == -1) {
			printf("get app metadata list failed\n");
			goto end;
		}
	}  else if (strcmp(argv[1], "--appcontrol") == 0) {
		ret = __get_app_control_list(argv[2]);
		if (ret == -1) {
			printf("get app control list failed\n");
			goto end;
		}
	} else
		__print_usage();

end:
	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	printf("spend time for pkginfo is [%d]ms\n", (int)(endtime - starttime));

	return ret;
}
