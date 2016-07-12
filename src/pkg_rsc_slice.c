
/*
 * pkgmgr-tool
 *
 * Copyright (c) 2015-2016 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <glib.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <sys/time.h>
#include "aul_rsc_mgr.h"

#define RSC_TOOL_VERSION	"0.1"
#define BUF_SIZE 1024

static int __process_slice(void);
static void __print_usage();

struct rsc_tool_args_t {
	char res_path[PATH_MAX];
	int dpi;
	int bpp;
	char dpi_range[BUF_SIZE];
	char width_range[BUF_SIZE];
	char screen_large[BUF_SIZE];
	char platform_version[BUF_SIZE];
};

typedef struct rsc_tool_args_t rsc_tool_args;
rsc_tool_args data;
GHashTable *valid_file_list;

const char *short_options = "p:d:";

const struct option long_options[] = {
	{"path", 1, NULL, 'p'},
	{"screen-dpi", 1, NULL, 'd'},
	{0, 0, 0, 0}		/* sentinel */
};


static int __convert_to_abs_path(char *path)
{
	char abs[BUF_SIZE] = {'\0'};
	char cwd[BUF_SIZE] = {'\0'};
	char *buf = NULL;
	int ret = -1;

	if (path == NULL) {
		printf("invalid path\n");
		return -1;
	}

	buf = getcwd(cwd, BUF_SIZE - 1);
	if (buf == NULL) {
		printf("failed to get cwd\n");
		return -1;
	}

	ret = chdir(path);
	if (ret < 0) {
		printf("failed to change dir[%s]\n", path);
		return -1;
	}

	buf = getcwd(abs, BUF_SIZE - 1);
	if (buf == NULL) {
		printf("failed to get cwd\n");
		return -1;
	}

	memset(data.res_path, '\0', BUF_SIZE);
	snprintf(data.res_path, BUF_SIZE - 1, "%s/", abs);
	ret = chdir(cwd);
	if (ret < 0) {
		printf("failed to change dir[%s]\n", path);
		return -1;
	}

	return 0;
}

static void __print_usage()
{
	printf("\nResource Slicing Tool Version: %s\n\n", RSC_TOOL_VERSION);
	printf("-p, --path		     set resource path\n");
	printf("-d, --screen-dpi     set screen dpi value\n");

	printf("Usage: rscslice [options] \n");
	printf("rsc-slice -p [res path] \n");
	printf("rsc-slice -p [res_path] -d [dpi value] \n");

	printf("Example:\n");
	printf("rsc-slice -p /home/userid/workspace/testapp/res/ \n");
	printf("rsc-slice -p /home/userid/workspace/testapp/res/ -d 300 \n");

	exit(0);
}

static void __del_file(char *path)
{
	struct dirent **items;
	struct stat fstat;
	char abs_path[1024] = {0, };
	char cwd[1024] = {0, };
	char *tmp = NULL;
	int nitems, i;

	if (chdir(path) < 0) {
		printf("failed to chdir[%s]\n", path);
		return;
	}

	tmp = getcwd(cwd, 1024 - 1);
	nitems = scandir("./", &items, NULL, alphasort);

	for (i = 0; i < nitems; i++) {
		if (items[i]->d_name[0] == '.')
			continue;

		snprintf(abs_path, 1024 - 1, "%s/%s", cwd, items[i]->d_name);
		if (g_lstat(abs_path, &fstat) != 0) {
			printf("failed to get info[%s]\n", abs_path);
			return;
		}
		if ((fstat.st_mode & S_IFDIR) == S_IFDIR) {
			__del_file(abs_path);
		} else {
			tmp = g_hash_table_lookup(valid_file_list, abs_path);
			if (tmp == NULL) {
				printf("deleting [%s]\n", abs_path);
				remove(abs_path);
			}
		}
	}
}

static int __process_slice(void)
{
	int ret = -1;
	bundle *b = NULL;
	char dpi_value[1024] = {0, };

	if (data.res_path[0] == '\0')
		return -1;

	b = bundle_create();
	if (data.dpi != 0) {
		snprintf(dpi_value, 1024 - 1, "%d", data.dpi);
		bundle_add_str(b, "screen-dpi", dpi_value);
	}

	/* other attributes will be added here*/

	ret = aul_resource_manager_init_slice(data.res_path, b);
	if (ret < 0) {
		printf("failed to init rsc manager\n");
		goto catch;
	}

	ret = aul_resource_manager_get_path_list(&valid_file_list);
	if (ret < 0) {
		printf("failed to init rsc manager\n");
		goto catch;
	}

	/* remove useless resources and empty directories */
	__del_file(data.res_path);


catch:
	if (aul_resource_manager_release() < 0)
		printf("failed to release resource manager\n");

	bundle_free(b);
	return ret;
}

int main(int argc, char *argv[])
{
	optind = 1;
	int opt_idx = 0;
	int c = -1;
	int ret = 0;
	long starttime;
	long endtime;
	int i = 0;
	struct timeval tv;

	if (argc == 1)
		__print_usage();

	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	/* initialization of global structure */
	data.dpi = 0;
	data.bpp = 0;
	memset(data.dpi_range, '\0', BUF_SIZE);
	memset(data.width_range, '\0', BUF_SIZE);
	memset(data.screen_large, '\0', BUF_SIZE);
	memset(data.platform_version, '\0', BUF_SIZE);

	while (1) {
		i++;
		c = getopt_long(argc, argv, short_options, long_options, &opt_idx);
		if (c == -1)
			break;	/* Parse end */
		switch (c) {
		case 'p':	/* resource path */
			if (optarg)
				strncpy(data.res_path, optarg, PATH_MAX - 1);

			ret = __convert_to_abs_path(data.res_path);
			if (ret == -1) {
				printf("conversion of relative path to absolute path failed\n");
				return -1;
			}
			printf("path is [%s]\n", data.res_path);
			break;

		case 'd':	/* set dpi */
			if (optarg)
				data.dpi = atoi(optarg);

			if (data.dpi == 0) {
				printf("failed to get dpi value\n");
				return -1;
			}
			printf("dpi value is [%d]\n", data.dpi);
			break;

		default:
			break;

		}
	}

	ret = __process_slice();

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;
	printf("spend time for rsc-slice is [%d]ms\n", (int)(endtime - starttime));

	return 0;
}
