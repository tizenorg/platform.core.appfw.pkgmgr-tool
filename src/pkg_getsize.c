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

#include <pkgmgr-info.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

/* For multi-user support */
#include <tzplatform_config.h>

#include <package-manager.h>
#include <package-manager-debug.h>
#include <pkgmgr_installer.h>
#include <pkgmgr/comm_config.h>

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_GETSIZE"
#endif				/* LOG_TAG */

#define MAX_PKG_BUF_LEN			1024
#define BLOCK_SIZE      		4096 /*in bytes*/
#define MAX_PATH_LENGTH 		512
#define MAX_LONGLONG_LENGTH 	32
#define MAX_SIZE_INFO_SIZE 		128

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#if 0 /* installed at external storage is not supported yet */
#define APP_BASE_EXTERNAL_PATH ""
#endif

typedef enum
{
	STORAGE_TYPE_INTERNAL,
	STORAGE_TYPE_EXTERNAL,
	STORAGE_TYPE_MAX = 255,
} STORAGE_TYPE;

long long __stat_size(struct stat *s)
{
	long long blksize = s->st_blksize;
	long long size = (long long)s->st_blocks * 512;

	if (blksize) {
		size = (size + blksize - 1) & (~(blksize - 1));
	}

	return size;
}

static long long __calculate_directory_size(int dfd, bool include_itself)
{
	long long size = 0;
	struct stat st;
	int subfd;
	int ret;
	DIR *dir;
	struct dirent *dent;
	const char *entry;

	if (include_itself) {
		ret = fstat(dfd, &st);
		if (ret < 0) {
			ERR("fstat() failed, entry: ., errno: %d (%s)", errno,
					strerror(errno));
			return -1;
		}
		size += __stat_size(&st);
	}

	dir = fdopendir(dfd);
	if (dir == NULL) {
		ERR("fdopendir() failed, errno: %d (%s)", errno,
				strerror(errno));
		return -1;
	}

	while ((dent = readdir(dir))) {
		entry = dent->d_name;
		if (entry[0] == '.') {
			if (entry[1] == '\0')
				continue;
			if ((entry[1] == '.') && (entry[2] == '\0'))
				continue;
		}

		if (dent->d_type == DT_DIR) {
			subfd = openat(dfd, entry, O_RDONLY | O_DIRECTORY);
			if (subfd < 0) {
				ERR("openat() failed, entry:%s, errno: %d(%s)",
						entry, errno, strerror(errno));
				goto error;
			}

			DBG("traverse entry: %s", entry);
			size += __calculate_directory_size(subfd, true);
			close(subfd);
		} else {
			ret = fstatat(dfd, entry, &st, AT_SYMLINK_NOFOLLOW);
			if (ret < 0) {
				ERR("fstatat() failed, entry:%s, errno: %d(%s)",
						entry, errno, strerror(errno));
				goto error;
			}
			size += __stat_size(&st);
		}
	}

	closedir(dir);
	return size;

error:
	closedir(dir);
	return -1;
}

static long long __calculate_shared_dir_size(int dfd, const char *app_root_dir,
		long long *data_size, long long *app_size)
{
	int fd = -1;
	int subfd = -1;
	long long size = 0;
	struct stat st;
	int ret;

	DBG("traverse path: %s/shared", app_root_dir);

	fd = openat(dfd, "shared", O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		ERR("openat() failed, path: %s/shared, errno: %d (%s)",
				app_root_dir, errno, strerror(errno));
		return -1;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		ERR("fstat() failed, path: %s/shared, errno: %d (%s)",
				app_root_dir, errno, strerror(errno));
		goto error;
	}
	*app_size += __stat_size(&st); // shared directory
	DBG("app_size: %lld", *app_size);

	DBG("traverse path: %s/shared/data", app_root_dir);

	subfd = openat(fd, "data", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0) {
		size = __calculate_directory_size(subfd, true);
		if (size < 0)
		{
			ERR("Calculating shared/data directory failed.");
			goto error;
		}
		*data_size += size;
		DBG("data_size: %lld", *data_size);
		close(subfd);
	} else if (subfd < 0 && errno != ENOENT) {
		ERR("openat() failed, entry: data, errno: %d (%s)",
				errno, strerror(errno));
		goto error;
	}

	DBG("traverse path: %s/shared/trusted", app_root_dir);

	subfd = openat(fd, "trusted", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0) {
		size = __calculate_directory_size(subfd, true);
		if (size < 0) {
			ERR("Calculating shared/trusted directory failed.");
			goto error;
		}
		*data_size += size;
		DBG("data_size: %lld", *data_size);
		close(subfd);
	} else if (subfd < 0 && errno != ENOENT) {
		DBG("openat() failed, entry: trusted, errno: %d (%s)",
				errno, strerror(errno));
		goto error;
	}

	DBG("traverse path: %s/shared/res", app_root_dir);

	subfd = openat(fd, "res", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0) {
		size = __calculate_directory_size(subfd, true);
		if (size < 0) {
			ERR("Calculating shared/res directory failed.");
			goto error;
		}
		*app_size += size;
		DBG("app_size: %lld", *app_size);
		close(subfd);
	} else if (subfd < 0 && errno != ENOENT) {
		ERR("openat() failed, entry: res, errno: %d (%s)",
				errno, strerror(errno));
		goto error;
	}

	DBG("traverse path: %s/shared/cache", app_root_dir);

	subfd = openat(fd, "cache", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0) {
		size = __calculate_directory_size(subfd, true);
		if (size < 0) {
			ERR("Calculating shared/cache directory failed.");
			goto error;
		}
		*data_size += size;
		DBG("data_size: %lld", *data_size);
		close(subfd);
	} else if (subfd < 0 && errno != ENOENT) {
		ERR("openat() failed, entry: data, errno: %d (%s)",
				errno, strerror(errno));
		goto error;
	}

	close(fd);
	return 0;

error:
	if (fd != -1)
		close(fd);
	if (subfd != -1)
		close(subfd);

	return -1;
}

static int __is_global(uid_t uid)
{
	return (uid == OWNER_ROOT || uid == GLOBAL_USER) ? 1 : 0;
}

static int __calculate_pkg_size_info(STORAGE_TYPE type, const char *pkgid,
		long long *data_size, long long *cache_size,
		long long *app_size)
{
	uid_t uid = getuid();
	char app_root_dir[MAX_PATH_LENGTH] = {0, };
	DIR *dir;
	int dfd;
	int subfd = -1;
	struct stat st;
	int ret;
	struct dirent *ent;
	long long size = 0;

	if (type == STORAGE_TYPE_INTERNAL) {
		if (!__is_global(uid))
			tzplatform_set_user(uid);
		snprintf(app_root_dir, sizeof(app_root_dir), "%s",
				tzplatform_mkpath(__is_global(uid)
					? TZ_SYS_RW_APP : TZ_USER_APP, pkgid));
		tzplatform_reset_user();
#if 0 /* installed at external storage is not supported yet */
	} else if (type == STORAGE_TYPE_EXTERNAL) {
		snprintf(app_root_dir, MAX_PATH_LENGTH, "%s%s/",
				APP_BASE_EXTERNAL_PATH, pkgid);
#endif
	} else {
		ERR("Invalid STORAGE_TYPE");
		return -1;
	}

	dir = opendir(app_root_dir);
	if (dir == NULL) {
		ERR("opendir() failed, path: %s, errno: %d (%s)",
				app_root_dir, errno, strerror(errno));
		return -1;
	}

	dfd = dirfd(dir);
	ret = fstat(dfd, &st);
	if (ret < 0) {
		ERR("fstat() failed, path: %s, errno: %d (%s)", app_root_dir,
				errno, strerror(errno));
		goto error;
	}
	*app_size += __stat_size(&st);

	while ((ent = readdir(dir))) {
		const char *name = ent->d_name;
		if (name[0] == '.') {
			if (name[1] == '\0')
				continue;
			if ((name[1] == '.') && (name[2] == '\0'))
				continue;
		}

		if (ent->d_type != DT_DIR)
			continue;

		subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
		if (subfd < 0) {
			if (errno != ENOENT) {
				ERR("openat() failed, errno: %d (%s)",
						errno, strerror(errno));
				goto error;
			}
			continue;
		}
		if (strncmp(name, "data", strlen("data")) == 0) {
			DBG("traverse path: %s/%s", app_root_dir, name);
			size = __calculate_directory_size(subfd, true);
			if (size < 0) {
				ERR("Calculating data directory failed.");
				goto error;
			}
			*data_size += size;
			DBG("data_size: %lld", *data_size);
		} else if (strncmp(name, "cache", strlen("cache")) == 0) {
			DBG("traverse path: %s/%s", app_root_dir, name);
			size = __calculate_directory_size(subfd, true);
			if (size < 0) {
				ERR("Calculating cache directory failed.");
				goto error;
			}
			*cache_size += size;
			DBG("cache_size: %lld", *cache_size);
		} else if (strncmp(name, "shared", strlen("shared")) == 0) {
			size = __calculate_shared_dir_size(dfd, app_root_dir,
					data_size, app_size);
			if (size < 0) {
				ERR("Calculating shared directory failed.");
				goto error;
			}
			*app_size += size;
			DBG("app_size: %lld", *app_size);
		} else {
			DBG("traverse path: %s/%s", app_root_dir, name);
			size = __calculate_directory_size(subfd, true);
			if (size < 0) {
				ERR("Calculating %s directory failed.", name);
				goto error;
			}
			*app_size += size;
			DBG("app_size: %lld", *app_size);
		}
		close(subfd);
	}
	closedir(dir);
	return 0;

error:
	if (dir)
		closedir(dir);
	if (subfd != -1)
		close(subfd);

	return -1;
}

static char *__get_pkg_size_info_str(const pkg_size_info_t* pkg_size_info)
{
	char *size_info_str;

	size_info_str = (char *)malloc(MAX_SIZE_INFO_SIZE);
	if (size_info_str == NULL) {
		ERR("Out of memory.");
		return NULL;
	}

	snprintf(size_info_str, MAX_SIZE_INFO_SIZE, "%lld",
			pkg_size_info->data_size);
	strncat(size_info_str, ":", MAX_SIZE_INFO_SIZE - strlen(size_info_str)- 1);
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH,
			"%lld", pkg_size_info->cache_size);
	strncat(size_info_str, ":", MAX_SIZE_INFO_SIZE - strlen(size_info_str)- 1);
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH,
			"%lld", pkg_size_info->app_size);
	strncat(size_info_str, ":", MAX_SIZE_INFO_SIZE - strlen(size_info_str)- 1);
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH,
			"%lld", pkg_size_info->ext_data_size);
	strncat(size_info_str, ":", MAX_SIZE_INFO_SIZE - strlen(size_info_str)- 1);
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH,
			"%lld", pkg_size_info->ext_cache_size);
	strncat(size_info_str, ":", MAX_SIZE_INFO_SIZE - strlen(size_info_str)- 1);
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH,
			"%lld", pkg_size_info->ext_app_size);
	strncat(size_info_str, ":", MAX_SIZE_INFO_SIZE - strlen(size_info_str)- 1);

	DBG("size_info_str: %s", size_info_str);

	return size_info_str;
}

static int __get_pkg_size_info(const char *pkgid,
		pkg_size_info_t *pkg_size_info)
{
	int ret;

	ret = __calculate_pkg_size_info(STORAGE_TYPE_INTERNAL, pkgid,
			&pkg_size_info->data_size, &pkg_size_info->cache_size,
			&pkg_size_info->app_size);
	if (ret < 0)
		DBG("Calculating internal package size info failed: %d", ret);
	DBG("size_info: %lld %lld %lld", pkg_size_info->data_size,
			pkg_size_info->cache_size, pkg_size_info->app_size);

#if 0
	ret = __calculate_pkg_size_info(STORAGE_TYPE_EXTERNAL, pkgid,
			&pkg_size_info->ext_data_size,
			&pkg_size_info->ext_cache_size,
			&pkg_size_info->ext_app_size);
	if (ret < 0)
		DBG("Calculating external package size info failed: %d", ret);
	DBG("size_info(external): %lld %lld %lld", pkg_size_info->ext_data_size,
			pkg_size_info->ext_cache_size,
			pkg_size_info->ext_app_size);
#endif
	return ret;
}

static int __get_total_pkg_size_info_cb(const pkgmgrinfo_pkginfo_h handle,
		void *user_data)
{
	int ret;
	char *pkgid;
	pkg_size_info_t temp_pkg_size_info = {0,};
	pkg_size_info_t *pkg_size_info = (void *)user_data;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK) {
		ERR("pkgmgrinfo_pkginfo_get_pkgid() failed");
		return -1;
	}

	__get_pkg_size_info(pkgid, &temp_pkg_size_info);

	pkg_size_info->app_size += temp_pkg_size_info.app_size;
	pkg_size_info->data_size += temp_pkg_size_info.data_size;
	pkg_size_info->cache_size += temp_pkg_size_info.cache_size;
	pkg_size_info->ext_app_size += temp_pkg_size_info.ext_app_size;
	pkg_size_info->ext_data_size += temp_pkg_size_info.ext_data_size;
	pkg_size_info->ext_cache_size += temp_pkg_size_info.ext_cache_size;

	return 0;
}

int __make_size_info_file(char *req_key, long long size)
{
	FILE *file;
	int fd = 0;
	char buf[MAX_PKG_BUF_LEN];
	char info_file[MAX_PKG_BUF_LEN];

	if (req_key == NULL)
		return -1;

	snprintf(info_file, sizeof(info_file), "%s/%s", PKG_SIZE_INFO_PATH,
			req_key);
	ERR("File path = %s", info_file);

	file = fopen(info_file, "w");
	if (file == NULL) {
		ERR("Couldn't open the file %s", info_file);
		return -1;
	}

	snprintf(buf, MAX_LONGLONG_LENGTH, "%lld", size);
	fwrite(buf, 1, strlen(buf), file);

	fflush(file);
	fd = fileno(file);
	fsync(fd);
	fclose(file);

	return 0;
}

static int __send_sizeinfo_cb(const pkgmgrinfo_pkginfo_h handle,
		void *user_data)
{
	int ret;
	char *pkgid;
	int data_size = 0;
	int total_size = 0;
	char total_buf[MAX_PKG_BUF_LEN];
	char data_buf[MAX_PKG_BUF_LEN];
	pkgmgr_installer *pi = (pkgmgr_installer *)user_data;

	pkg_size_info_t temp_pkg_size_info = {0, };

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK) {
		ERR("pkgmgrinfo_pkginfo_get_pkgid() failed");
		return -1;
	}

	__get_pkg_size_info(pkgid, &temp_pkg_size_info);

	total_size = temp_pkg_size_info.app_size +
		temp_pkg_size_info.data_size + temp_pkg_size_info.cache_size;
	data_size = temp_pkg_size_info.data_size +
		temp_pkg_size_info.cache_size;

	/* send size info to client */
	snprintf(total_buf, sizeof(total_buf), "%d", total_size);
	snprintf(data_buf, sizeof(data_buf), "%d", data_size);

	return pkgmgr_installer_send_signal(pi,
			PKGMGR_INSTALLER_GET_SIZE_KEY_STR,
			pkgid, data_buf, total_buf);
}

static int __send_result_to_signal(pkgmgr_installer *pi, const char *req_key,
		const char *pkgid, pkg_size_info_t *info)
{
	int ret;
	char *info_str;

	info_str = __get_pkg_size_info_str(info);
	if (info_str == NULL)
		return -1;

	ret = pkgmgr_installer_send_signal(pi,
			PKGMGR_INSTALLER_GET_SIZE_KEY_STR,
			pkgid, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, info_str);
	free(info_str);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	int get_type;
	char *pkgid;
	char *req_key;
	long long size = 0;
	pkgmgr_installer *pi;
	pkg_size_info_t info = {0, };

	// argv has bellowed meaning
	// argv[1] = pkgid
	// argv[2] = get type
	// argv[4] = req_key

	if (argv[1] == NULL) {
		ERR("pkgid is NULL");
		return -1;
	}

	pkgid = argv[1];
	get_type = atoi(argv[2]);
	req_key = argv[4];

	DBG("start get size : [pkgid=%s, request type=%d]", pkgid, get_type);

	pi = pkgmgr_installer_new();
	if (pi == NULL) {
		ERR("failed to create installer");
		return -1;
	}
	pkgmgr_installer_receive_request(pi, argc, argv);

	switch (get_type) {
	case PM_GET_TOTAL_SIZE:
		/* send result to file */
		ret = __get_pkg_size_info(pkgid, &info);
		if (ret == 0)
			size = info.app_size + info.data_size + info.cache_size;
		ret = __make_size_info_file(req_key, size);
		break;
	case PM_GET_DATA_SIZE:
		/* send result to file */
		ret = __get_pkg_size_info(pkgid, &info);
		if (ret == 0)
			size = info.data_size + info.cache_size;
		ret = __make_size_info_file(req_key, size);
		break;
	case PM_GET_ALL_PKGS:
		/* send result to file */
		ret = pkgmgrinfo_pkginfo_get_usr_list(
				__get_total_pkg_size_info_cb, &info, getuid());
		if (ret == 0)
			size = info.app_size + info.data_size + info.cache_size;
		ret = __make_size_info_file(req_key, size);
		break;
	case PM_GET_SIZE_INFO:
		/* send each result to signal */
		ret = pkgmgrinfo_pkginfo_get_usr_list(__send_sizeinfo_cb, pi,
				getuid());
		ret = __make_size_info_file(req_key, 0);
		break;
	case PM_GET_PKG_SIZE_INFO:
		/* send result to signal */
		ret = __get_pkg_size_info(pkgid, &info);
		if (ret == 0)
			ret = __send_result_to_signal(pi, req_key,
					pkgid, &info);
		ret = __make_size_info_file(req_key, 0);
		break;
	case PM_GET_TOTAL_PKG_SIZE_INFO:
		/* send result to signal */
		ret = pkgmgrinfo_pkginfo_get_usr_list(
				__get_total_pkg_size_info_cb, &info, getuid());
		if (ret == 0)
			ret = __send_result_to_signal(pi, req_key,
					PKG_SIZE_INFO_TOTAL, &info);
		ret = __make_size_info_file(req_key, 0);
		break;
	default:
		ret = -1;
		ERR("unsupported or depreated type");
		break;
	}

	if (pkgmgr_installer_send_signal(pi, PKGMGR_INSTALLER_GET_SIZE_KEY_STR,
				pkgid, PKGMGR_INSTALLER_GET_SIZE_KEY_STR,
				PKGMGR_INSTALLER_END_KEY_STR))
		ERR("failed to send finished signal");

	DBG("get size result = %d", ret);
	pkgmgr_installer_free(pi);

	return ret;
}
