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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dlog.h>
#include <tzplatform_config.h>
#include <pkgmgr-info.h>
#include <package-manager.h>

#define MAX_PKG_NAME_LEN	256
#define INTERNAL_CACHE_PATH_PREFIX tzplatform_getenv(TZ_USER_APP)
#define EXTERNAL_CACHE_PATH_PREFIX tzplatform_mkpath(TZ_SYS_MEDIA, "SDCardA1/apps")
#define CACHE_PATH_POSTFIX "/cache"
#define SHARED_PATH_POSTFIX "/shared/cache"


#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_CLEARCACHE"
#endif				/* LOG_TAG */

static int __clear_dir(const char *dirname)
{
	int ret = 0;
	DIR *dp = NULL;
	char buf[1024] = {0, };
	struct dirent ep, *result;
	char *abs_filename = NULL;
	struct stat stFileInfo;

	LOGD("Cache directory name to clear [%s]\n", dirname);

	abs_filename = (char *)malloc(sizeof(char) * PATH_MAX);
	if (abs_filename == NULL) {
		LOGE("Memory allocation failed\n");
		goto err;
	}

	dp = opendir(dirname);
	if (dp == NULL) {
		if (errno == ENOENT) {
			LOGD("no entry, path(%s)", dirname);
			free(abs_filename);
			return 0;
		}
		LOGE("Couldn't open the directory. errno : %d (%s)\n", errno,
			strerror_r(errno, buf, sizeof(buf)));
		goto err;
	}

	for (ret = readdir_r(dp, &ep, &result);
		ret == 0 && result != NULL;
		ret = readdir_r(dp, &ep, &result)) {
		snprintf(abs_filename, PATH_MAX - 1, "%s/%s", dirname,
			ep.d_name);
		if (lstat(abs_filename, &stFileInfo) < 0)
			perror(abs_filename);

		if (S_ISDIR(stFileInfo.st_mode)) {
			if (strcmp(ep.d_name, ".") &&
				strcmp(ep.d_name, "..")) {
				ret = __clear_dir(abs_filename);
				if (ret != 0)
					LOGE("Couldn't remove the directory. "
						"errno : %d (%s)\n",
						errno, strerror_r(errno, buf, sizeof(buf)));

				ret = remove(abs_filename);
				if (ret != 0) {
					LOGE("Couldn't remove the directory. "
						"errno : %d (%s)\n",
						errno, strerror_r(errno, buf, sizeof(buf)));
					goto err;
				}
			}
		} else {
			ret = remove(abs_filename);
			if (ret != 0) {
				LOGE("Couldn't remove the directory. errno : "
					"%d (%s)\n", errno,
					strerror_r(errno, buf, sizeof(buf)));
				goto err;
			}
		}
	}
	closedir(dp);
	free(abs_filename);

	return 0;

err:
	if (abs_filename)
		free(abs_filename);
	if (dp)
		closedir(dp);

	return -1;
}

static int __clear_cache_dir(const char *pkgid)
{
	int ret = 0;
	uid_t uid = getuid();
	char dirname[PATH_MAX] = {0,};

	if (pkgid == NULL) {
		LOGE("pkgid is NULL\n");
		return -1;
	}

	/* cache internal */
	snprintf(dirname, sizeof(dirname), "%s/%s%s",
		INTERNAL_CACHE_PATH_PREFIX, pkgid, CACHE_PATH_POSTFIX);

	ret = __clear_dir(dirname);
	if (ret < 0)
		LOGE("Failed to clear internal cache dir.");

	/* shared/cache internal */
	snprintf(dirname, sizeof(dirname), "%s/%s%s",
		INTERNAL_CACHE_PATH_PREFIX, pkgid, SHARED_PATH_POSTFIX);

	ret = __clear_dir(dirname);
	if (ret < 0)
		LOGE("Failed to clear internal shared cache dir.");

	/* cache external */
	tzplatform_set_user(uid);

	snprintf(dirname, sizeof(dirname), "%s%s%s",
		EXTERNAL_CACHE_PATH_PREFIX,
		tzplatform_mkpath(TZ_USER_NAME, pkgid),
		CACHE_PATH_POSTFIX);

	ret = __clear_dir(dirname);
	if (ret < 0)
		LOGE("Failed to clear external cache dir.");

	/* shared/cache external */
	snprintf(dirname, sizeof(dirname), "%s%s%s",
		EXTERNAL_CACHE_PATH_PREFIX,
		tzplatform_mkpath(TZ_USER_NAME, pkgid),
		SHARED_PATH_POSTFIX);

	tzplatform_reset_user();

	ret = __clear_dir(dirname);
	if (ret < 0)
		LOGE("Failed to clear external shared cache dir.");


	return 0;
}

static int __clear_all_cache_dir_cb(const pkgmgrinfo_pkginfo_h handle,
		void *user_data)
{
	int res = 0;
	char *pkgid;
	int *err_cnt = (int *)user_data;

	res = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (res != PMINFO_R_OK) {
		LOGE("pkgmgr_pkginfo_get_pkgid() failed");
		--(*err_cnt);
		return 0;
	}

	res = __clear_cache_dir(pkgid);
	if (res != 0) {
		LOGE("Failed to clear cache dir of %s", pkgid);
		--(*err_cnt);
		return 0;
	}

	return 0;
}

static int __clear_all_cache_dir(void)
{
	int err_cnt = 0;
	int res;

	res = pkgmgrinfo_pkginfo_get_usr_list(__clear_all_cache_dir_cb,
		&err_cnt, getuid());
	if (res != PMINFO_R_OK) {
		LOGE("Failed to get pkg list. (%d)", res);
		return -1;
	} else if (err_cnt != 0) {
		LOGE("Error occured in %d packages.", err_cnt);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	char pkgid[MAX_PKG_NAME_LEN];

	if (argc < 2) {
		LOGE("pkgid is NULL\n");
		return -1;
	}

	snprintf(pkgid, sizeof(pkgid), "%s", argv[1]);

	if (strcmp(pkgid, PKG_CLEAR_ALL_CACHE) == 0)
		ret = __clear_all_cache_dir();
	else
		ret = __clear_cache_dir(pkgid);

	return ret;
}
