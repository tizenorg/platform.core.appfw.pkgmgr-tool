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
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define BUFSZE 4096

#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[TPK_PRELOAD_INSTALL][E][%s,%d] \
	 "fmt"\n", __FUNCTION__, __LINE__, ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[TPK_PRELOAD_INSTALL][D][%s,%d] \
	"fmt"\n", __FUNCTION__, __LINE__, ##arg);

#define BACKEND_CMD "/usr/bin/tpk-backend"

static int _install_preload_tpk(const char *directory)
{
	DIR *dir;
	struct dirent file_info, *result;
	int ret;
	char file_path[BUFSZE];
	char err_buf[BUFSZE];

	dir = opendir(directory);
	if (!dir) {
		if (errno == ENOENT) {
			_D("The directory for preloaded tpks doesn't exist");
			return 0;
		} else {
			_E("Failed to access the [%s] because [%s]", directory,
				strerror_r(errno, err_buf, sizeof(err_buf)));
			return -1;
		}
	}

	_D("Loading tpk files from %s", directory);

	for (ret = readdir_r(dir, &file_info, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &file_info, &result)) {
		if (file_info.d_name[0] == '.')
			continue;

		snprintf(file_path, sizeof(file_path), "%s/%s", directory,
			file_info.d_name);
		_D("tpk file %s", file_path);

		pid_t pid = fork();
		if (pid == 0) {
			execl(BACKEND_CMD, BACKEND_CMD, "-i", file_path,
				"--preload", (char *)NULL);
		} else if (pid < 0) {
			_E("failed to fork and execute %s!", BACKEND_CMD);
			closedir(dir);
			return -1;
		}

		if (pid > 0) {
			int status = 0;
			waitpid(pid, &status, 0);
		}

		/* remove a file after installation */
		ret = remove(file_path);
		if (ret < 0) {
			_E("Failed to remove the file [%s] because [%s]",
				file_path, strerror_r(errno, err_buf,
				sizeof(err_buf)));
			closedir(dir);
			return -1;
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
	char err_msg[BUFSZE];
	const char *dir = tzplatform_mkpath(TZ_SYS_RO_APP, ".preload-tpk");
	int handle = -1;
	int ret = 0;

	if (!_is_authorized(getuid())) {
		_E("You are not an authorized user!");
		return -1;
	}

	if (_install_preload_tpk(dir) < 0) {
		handle = open("/tmp/.preload_install_error",
			O_WRONLY|O_CREAT|O_APPEND|O_TRUNC, 0644);
		if (handle == -1) {
			_E("Failed to open error file");
			return -1;
		}
		snprintf(err_msg, sizeof(err_msg),
			"install_preload_tpk error!\n");
		ret = write(handle, err_msg, strlen(err_msg));
		if (ret == -1)
			_E("Failed to write an error message. (%d)", errno);
		close(handle);
		return -1;
	}

	return 0;
}
