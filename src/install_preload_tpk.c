/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define BUFSZE 4096

#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[TPK_PRELOAD_INSTALL][E][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[TPK_PRELOAD_INSTALL][D][%s,%d] "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#define BACKEND_CMD "/usr/bin/tpk-backend"

static int _install_preload_tpk(uid_t uid, const char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char buf[BUFSZE];

	dir = opendir(directory);
	if (!dir) {
		_E("Failed to access the [%s] because %s", directory,
				strerror_r(errno, buf, sizeof(buf)));
		return -1;
	}

	_D("Loading tpk files from %s", directory);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		if (entry.d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", directory, entry.d_name);
		_D("tpk file %s", buf);

		pid_t pid = fork();
		if (pid == 0) {
			setuid(uid);
			execl(BACKEND_CMD, BACKEND_CMD, "-i", buf, "--preload",
			      (char*)NULL);
		} else if (pid < 0) {
			_E("failed to fork and execute %s!", BACKEND_CMD);
			closedir(dir);
			return -1;
		}
		if (pid > 0) {
			int status = 0;
			waitpid(pid, &status, 0);
		}
	}

	closedir(dir);

	return 0;
}

static int _is_authorized(uid_t uid)
{
	/* install_preload_tpk should be called by as root privilege. */
	if ((uid_t) OWNER_ROOT == uid)
		return 1;
	else
		return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	const char *dir = tzplatform_mkpath(TZ_SYS_RO_APP, ".preload-tpk");
	uid_t uid = getuid();

	if (!_is_authorized(uid)) {
		_E("You are not an authorized user!");
		return -1;
	}

	return _install_preload_tpk(uid, dir);
}
