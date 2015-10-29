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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <pkgmgr_parser.h>
#include <pkgmgr_parser_db.h>
#include <pkgmgr-info.h>

#include <sys/smack.h>
/* For multi-user support */
#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define BUFSZE 1024

#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[PKG_INITDB][E][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[PKG_INITDB][D][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#define PKGINFO_CMD "/usr/bin/pkginfo --imd"
#define PKGINSTALLUG_CMD "/usr/bin/pkg_install_ug"
#define PKGPRIVILEGE_CMD "/usr/bin/pkg_privilege -i"

static int _is_global(uid_t uid)
{
	return (uid == OWNER_ROOT || uid == GLOBAL_USER) ? 1 : 0;
}

static int _initdb_load_directory(uid_t uid, const char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char buf[BUFSZE];
	char buf2[BUFSZE];

	dir = opendir(directory);
	if (!dir) {
		_E("Failed to access the [%s] because %s", directory,
				strerror_r(errno, buf, sizeof(buf)));
		return -1;
	}

	_D("Loading manifest files from %s", directory);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		if (entry.d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", directory, entry.d_name);
		_D("manifest file %s", buf);

		ret = pkgmgr_parser_check_manifest_validation(buf);
		if (ret < 0) {
			_E("check manifest validation failed code[%d] %s",
					ret, buf);
			continue;
		}

		if (setresuid(uid, uid, OWNER_ROOT)) {
			_E("Failed to setresuid: %s",
					strerror_r(errno, buf, sizeof(buf)));
			closedir(dir);
			return -1;
		}
		snprintf(buf2, sizeof(buf2), "%s %s", PKGINFO_CMD, buf);
		if (system(buf2))
			_E("[%s %s] returns error", PKGINFO_CMD, buf);
		snprintf(buf2, sizeof(buf2), "%s %s", PKGINSTALLUG_CMD, buf);
		if (system(buf2))
			_E("[%s %s] returns error", PKGINSTALLUG_CMD, buf);
		snprintf(buf2, sizeof(buf2), "%s %s", PKGPRIVILEGE_CMD, buf);
		if (system(buf2))
			_E("[%s %s] returns error", PKGPRIVILEGE_CMD, buf);
		if (setresuid(OWNER_ROOT, OWNER_ROOT, OWNER_ROOT)) {
			_E("Failed to setresuid: %s",
					strerror_r(errno, buf, sizeof(buf)));
			closedir(dir);
			return -1;
		}
	}

	closedir(dir);

	return 0;
}

static int _is_authorized()
{
	/* pkg_init db should be called by as root privilege. */
	uid_t uid = getuid();

	if ((uid_t) OWNER_ROOT == uid)
		return 1;
	else
		return 0;
}

static void _remove_old_dbs(uid)
{
	const char *info_db_path;
	const char *info_db_journal_path;
	const char *cert_db_path;
	const char *cert_db_journal_path;

	if (!_is_global(uid))
		tzplatform_set_user(uid);

	info_db_path = tzplatform_mkpath(
			_is_global(uid) ? TZ_SYS_DB : TZ_USER_DB,
			".pkgmgr_parser.db");
	info_db_journal_path = tzplatform_mkpath(
			_is_global(uid) ? TZ_SYS_DB : TZ_USER_DB,
			".pkgmgr_parser.db-journal");
	cert_db_path = tzplatform_mkpath(
			_is_global(uid) ? TZ_SYS_DB : TZ_USER_DB,
			".pkgmgr_cert.db");
	cert_db_journal_path = tzplatform_mkpath(
			_is_global(uid) ? TZ_SYS_DB : TZ_USER_DB,
			".pkgmgr_cert.db-journal");

	if (remove(info_db_path))
		_E(" %s is not removed", info_db_path);
	if (remove(info_db_journal_path))
		_E(" %s is not removed", info_db_journal_path);
	if (remove(cert_db_path))
		_E(" %s is not removed", cert_db_path);
	if (remove(cert_db_journal_path))
		_E(" %s is not removed", cert_db_journal_path);

	tzplatform_reset_user();
}

int main(int argc, char *argv[])
{
	int ret;
	const char *dir;
	uid_t uid = 0;

	if (!_is_authorized()) {
		_E("You are not an authorized user!");
		return -1;
	}

	if (argc > 1)
		uid = (uid_t)atoi(argv[1]);

	_remove_old_dbs(uid);

	ret = pkgmgr_parser_create_and_initialize_db(uid);
	if (ret < 0) {
		_E("cannot create db");
		return -1;
	}

	if (!_is_global(uid))
		tzplatform_set_user(uid);
	dir = tzplatform_getenv(
			_is_global(uid) ? TZ_SYS_RW_PACKAGES : TZ_USER_PACKAGES);
	tzplatform_reset_user();

	return _initdb_load_directory(uid, dir);
}
