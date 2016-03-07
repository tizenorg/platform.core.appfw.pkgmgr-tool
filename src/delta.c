/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Vivek Kumar <vivek.kumar2@samsung.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <glib.h>
#include <glib-object.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include "delta.h"

static GList *__list_directory(const char *dir_name, const char *tpk_path, GList *list);
static int __compare_files(char *path1, char *path2);
static void __print_to_file(char *msg);
static void __free_g_list(GList *list);

static void __free_g_list(GList *list)
{
	GList *iter = NULL;

	for (iter = list; iter != NULL; iter = iter->next) {
		if (iter->data)
			free(iter->data);
	}
	g_list_free(list);

	return;
}

static GList *__list_directory(const char *dir_name, const char *tpk_path, GList *list)
{
	DIR *dir = NULL;
	struct dirent file_info;
	struct dirent *result;
	int flag = 0;
	char path[PATH_MAX] = {0, };
	char rel_path_old_tpk_file[PATH_MAX] = {0, };
	char *file_path = NULL;
	char buf[BUF_SIZE] = {0};
	const char *d_name = NULL;
	int ret = 0;
	int path_length;

	dir = opendir(dir_name);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			printf("Cannot open directory '%s': %s\n", dir_name, buf);
		exit(EXIT_FAILURE);
	}

	while (1) {
		ret = readdir_r(dir, &file_info, &result);
		if (ret != 0 || result == NULL) {
			flag++;
			break;
		}

		d_name = file_info.d_name;
		if (!(file_info.d_type & DT_DIR)) {
			snprintf(rel_path_old_tpk_file, PATH_MAX, "%s/%s", dir_name, d_name);
			strncpy(path, rel_path_old_tpk_file + strlen(tpk_path),
					strlen(rel_path_old_tpk_file));
			file_path = strndup(path, sizeof(path));
			list = g_list_append(list, file_path);
			memset(path, 0, PATH_MAX);
			memset(rel_path_old_tpk_file, 0, PATH_MAX);
		}

		if (file_info.d_type & DT_DIR) {
			if (strcmp(d_name, "..") != 0 && strcmp(d_name, ".") != 0) {
				path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name, d_name);
				if (path_length >= PATH_MAX) {
					printf("Path length has got too long.\n");
					exit(EXIT_FAILURE);
				}
				list = __list_directory(path, tpk_path, list);
				memset(path, 0, PATH_MAX);
			}
		}
	}

	if (flag == 1) {
		snprintf(rel_path_old_tpk_file, PATH_MAX, "%s/", dir_name);
		strncpy(path, rel_path_old_tpk_file+strlen(tpk_path),
				strlen(rel_path_old_tpk_file));
		file_path = strndup(path, sizeof(path));
		list = g_list_prepend(list, file_path);
	}

	if (closedir(dir)) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			printf("Could not close '%s': %s\n", dir_name, buf);
		exit(EXIT_FAILURE);
	}

	return list;
}

static char *__create_md5Hash(char *file_name)
{
	FILE *inFile = fopen(file_name, "rb");
	unsigned char data[1024] = {0, };
	int bytes = 0;

	GChecksum *checksum = NULL;
	char *checksum_val = NULL;
	char *return_val = NULL;

	if (inFile == NULL) {
		printf("%s can't be opened.\n", file_name);
		return 0;
	}

	checksum = g_checksum_new(G_CHECKSUM_MD5);
	if (checksum == NULL) {
		printf("failed to create a new GChecksum\n");
		fclose(inFile);
		return 0;
	}

	while ((bytes = fread(data, 1, 1024, inFile)) != 0)
		g_checksum_update(checksum, (const guchar *)data, bytes);

	checksum_val = (char *)g_checksum_get_string(checksum);
	if (checksum_val)
		return_val = strdup(checksum_val);

	g_checksum_free(checksum);
	fclose(inFile);

	return return_val;
}

static int __compare_files(char *old_file, char *new_file)
{
	char *md5_old_file = NULL;
	char *md5_new_file = NULL;

	md5_old_file = __create_md5Hash(old_file);
	if (md5_old_file == NULL) {
		printf("md5checksum failed for %s.\n", old_file);
		exit(EXIT_FAILURE);
	}

	md5_new_file = __create_md5Hash(new_file);
	if (md5_new_file == NULL) {
		 printf("md5checksum failed for %s.\n", new_file);
		 exit(EXIT_FAILURE);
	}

	if (strcmp(md5_old_file, md5_new_file) == 0) {
		free(md5_old_file);
		free(md5_new_file);
		return 0;
	} else {
		free(md5_old_file);
		free(md5_new_file);
		return 1;
	}
}

static void __print_to_file(char *msg)
{
	 FILE *fp;

	 fp = fopen(DIFF_FILE, "a");

	 if (fp == NULL) {
		 printf("Cannot open %s for writing ", DIFF_FILE);
		 exit(1);
	 }

	 fprintf(fp, "%s \n", msg);
	 memset(msg, 0, MAX_MESSAGE_LEN);
	 fclose(fp);
}

void __create_diff_file(char *old_tpk_path, char *new_tpk_path)
{
	char rel_path_old_tpk_file[PATH_MAX] = {0, };
	char rel_path_new_tpk_file[PATH_MAX] = {0, };
	GList *list_dir_old_tpk = NULL;
	GList *list_dir_new_tpk = NULL;
	GList *iterator_old_tpk = NULL;
	GList *iterator_new_tpk = NULL;
	GList *next_iterator_old_tpk = NULL;
	GList *next_iterator_new_tpk = NULL;
	int ret = -1;

	list_dir_old_tpk = __list_directory(old_tpk_path, old_tpk_path, list_dir_old_tpk);
	list_dir_new_tpk = __list_directory(new_tpk_path, new_tpk_path, list_dir_new_tpk);
	if (list_dir_old_tpk == NULL) {
		printf("Could Not read %s\n", old_tpk_path);
		return;
	}

	if (list_dir_new_tpk == NULL) {
		printf("Could Not read %s\n", new_tpk_path);
		return;
	}

	iterator_old_tpk = list_dir_old_tpk;
	iterator_new_tpk = list_dir_new_tpk;

	while (iterator_old_tpk != NULL) {
		next_iterator_old_tpk = iterator_old_tpk->next;

		iterator_new_tpk = list_dir_new_tpk;
		while (iterator_new_tpk != NULL) {
			next_iterator_new_tpk = iterator_new_tpk->next;

			if (strcmp((char *)iterator_old_tpk->data,
					(char *)iterator_new_tpk->data) == 0) {
				snprintf(rel_path_old_tpk_file, PATH_MAX, "%s%s", old_tpk_path,
						(char *)iterator_old_tpk->data);
				snprintf(rel_path_new_tpk_file, PATH_MAX, "%s%s", new_tpk_path,
						(char *)iterator_new_tpk->data);
				ret = 0;
				if (rel_path_new_tpk_file[strlen(rel_path_new_tpk_file) - 1]
						!= '/') {
					ret = __compare_files(rel_path_old_tpk_file,
							rel_path_new_tpk_file);
					if (ret == 1) {
						snprintf(message, MAX_MESSAGE_LEN,
								"Files %s and %s differ",
								rel_path_old_tpk_file,
								rel_path_new_tpk_file);
						__print_to_file(message);
					}
				}
				list_dir_new_tpk = g_list_delete_link(list_dir_new_tpk,
						iterator_new_tpk);
				list_dir_old_tpk = g_list_delete_link(list_dir_old_tpk,
						iterator_old_tpk);
				iterator_new_tpk = next_iterator_new_tpk;
				iterator_old_tpk = next_iterator_old_tpk;
				break;
			}
			iterator_new_tpk = next_iterator_new_tpk;
		}
		iterator_old_tpk = next_iterator_old_tpk;
	}

	/* find if new file or new directory */
	iterator_old_tpk = list_dir_old_tpk;
	while (iterator_old_tpk != NULL) {
		iterator_new_tpk = iterator_old_tpk->next;
		while (iterator_new_tpk != NULL) {
			next_iterator_new_tpk = iterator_new_tpk->next;
			if (strstr(iterator_new_tpk->data, iterator_old_tpk->data) != NULL)
				list_dir_new_tpk = g_list_delete_link(list_dir_new_tpk,
						iterator_new_tpk);
			iterator_new_tpk = next_iterator_new_tpk;
		}
		iterator_old_tpk = iterator_old_tpk->next;
	}

	iterator_old_tpk = list_dir_new_tpk;
	while (iterator_old_tpk != NULL) {
		iterator_new_tpk = iterator_old_tpk->next;
		while (iterator_new_tpk != NULL) {
			next_iterator_new_tpk = iterator_new_tpk->next;
			if (strstr(iterator_new_tpk->data, iterator_old_tpk->data) != NULL)
				list_dir_new_tpk = g_list_delete_link(list_dir_new_tpk,
						iterator_new_tpk);
			iterator_new_tpk = next_iterator_new_tpk;
		}
		iterator_old_tpk = iterator_old_tpk->next;
	}

	iterator_old_tpk = list_dir_old_tpk;
	while (iterator_old_tpk != NULL) {
		snprintf(message, MAX_MESSAGE_LEN, "Only in %s%s", old_tpk_path,
				(char *)iterator_old_tpk->data);
		__print_to_file(message);
		iterator_old_tpk = iterator_old_tpk->next;
	}

	iterator_new_tpk = list_dir_new_tpk;
	while (iterator_new_tpk != NULL) {
		snprintf(message, MAX_MESSAGE_LEN, "Only in %s%s", new_tpk_path,
				(char *)iterator_new_tpk->data);
		__print_to_file(message);
		iterator_new_tpk = iterator_new_tpk->next;
	}

	/* to free GSList */
	__free_g_list(list_dir_old_tpk);
	__free_g_list(list_dir_new_tpk);
}

int __xsystem(const char *argv[])
{
	char buf[BUF_SIZE] = {0};
	int status = 0;
	pid_t pid;

	pid = fork();

	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		if (execvp(argv[0], (char *const *)argv) < 0) {
			if (strerror_r(errno, buf, sizeof(buf)) == 0)
				fprintf(stderr, "execvp failed %d....%s\n", errno, buf);
		}
		_exit(-1);
	default:
		/* parent */
		break;
	}

	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}

	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}

	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}

	return WEXITSTATUS(status);
}

