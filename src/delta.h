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

#ifndef DELTA_H_
#define DELTA_H_

#define DIFF_FILE		"/opt/usr/temp_delta/difffile.txt"
#define TEMP_DELTA_REPO		"/opt/usr/temp_delta/"
#define UNZIPFILE		"_FILES"
#define MAX_MESSAGE_LEN	1024
#define BUF_SIZE	1024
char message[MAX_MESSAGE_LEN];

void __create_diff_file(char *old_tpk_path, char *new_tpk_path);
int __xsystem(const char *argv[]);

#endif /* DELTA_H_ */
