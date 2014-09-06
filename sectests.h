/*
 *  Copyright 2014 c0defellas
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * sectests.h - Security Tests
 */

#ifndef SECTESTS_H
#define SECTESTS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <linux/limits.h>


struct tiny
{
	char *folder;
	char *file;
	char path[PATH_MAX];
	int file_size;
	char cmd_esp_1[PATH_MAX + 30];
	char cmd_esp_2[PATH_MAX + 30];
} tiny;

/* Tiny x86 binary that saves the esp for later analysis  */
const char *tiny_bytecode =
	"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	"\x00\x03\x00\x01\x00\x00\x00\x74\x80\x04\x08\x34\x00\x00\x00\x2c\x01"
	"\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x02\x00\x28\x00\x04\x00\x03"
	"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08"
	"\xff\x00\x00\x00\xff\x00\x00\x00\x05\x00\x00\x00\x00\x10\x00\x00\x01"
	"\x00\x00\x00\xff\x00\x00\x00\xff\x90\x04\x08\xff\x90\x04\x08\x14\x00"
	"\x00\x00\x14\x00\x00\x00\x06\x00\x00\x00\x00\x10\x00\x00\x83\x3c\x24"
	"\x03\x75\x14\xfc\x8b\x74\x24\x08\x8d\x3d\xff\x90\x04\x08\xb9\x04\x00"
	"\x00\x00\xf3\xa6\x74\x0c\xb8\x01\x00\x00\x00\xbb\x01\x00\x00\x00\xcd"
	"\x80\x54\x54\x8b\x74\x24\x14\x8d\x3d\x03\x91\x04\x08\xb9\x02\x00\x00"
	"\x00\xf3\xa6\x75\x08\x8d\x1d\x07\x91\x04\x08\xeb\x19\x8b\x74\x24\x14"
	"\x8d\x3d\x05\x91\x04\x08\xb9\x02\x00\x00\x00\xf3\xa6\x75\xc4\x8d\x1d"
	"\x0d\x91\x04\x08\xb8\x08\x00\x00\x00\xb9\xc0\x01\x00\x00\xcd\x80\x89"
	"\xc3\xb8\x04\x00\x00\x00\x89\xe1\xba\x04\x00\x00\x00\xcd\x80\xb8\x06"
	"\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80"
	"\x65\x73\x70\x00\x31\x00\x32\x00\x61\x64\x64\x72\x31\x00\x61\x64\x64"
	"\x72\x32\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65"
	"\x78\x74\x00\x2e\x64\x61\x74\x61\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x74\x80\x04\x08\x74"
	"\x00\x00\x00\x8b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
	"\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00"
	"\x00\xff\x90\x04\x08\xff\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x01\x00\x00\x17\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x00";

/* return 0 on success */
static int make_tiny_exec(void)
{
	int fd;
	int ret = 0;
	int written;

	tiny.folder = "/tmp";
	tiny.file = "tiny";

	strcpy(tiny.path, tiny.folder);
	strcat(tiny.path, "/");
	strcat(tiny.path, tiny.file);

	strcpy(tiny.cmd_esp_1, tiny.path);
	strcat(tiny.cmd_esp_1, " esp 1");

	strcpy(tiny.cmd_esp_2, tiny.path);
	strcat(tiny.cmd_esp_2, " esp 2");

	tiny.file_size = 460;

	fd = open(tiny.path, O_CREAT | O_WRONLY, S_IRWXU);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s\n", tiny.path);
		return -1;
	}

	written = write(fd, tiny_bytecode, tiny.file_size);
	if (written < tiny.file_size) {
		fprintf(stderr, "Written only %d of %d bytes\n", written, tiny.file_size);
		ret = -1;
	}

	if (close(fd) < 0)
		fprintf(stderr, "Can't close %s\n", tiny.path);

	return ret;
}

static void unmake_tiny_exec(void)
{
	if (remove("addr1") < 0)
		fprintf(stderr, "Was not possible to remove addr1\n");
	if (remove("addr2") < 0)
		fprintf(stderr, "Was not possible to remove addr2\n");
	if (remove(tiny.file) < 0)
		fprintf(stderr, "Was not possible to remove %s\n", tiny.file);
}

static _Bool aslr_enabled(void)
{
	system(tiny.cmd_esp_1);
	system(tiny.cmd_esp_2);

	return !(system("diff addr1 addr2 1> /dev/null") == 0);
}

static _Bool pie_enabled(void)
{
	//search in the own elf header
	return 1;
}

static _Bool nx_enabled(void){
	//search in the own elf header
	return 1;
}

/* Must be called from outside  */
static void sec_tests(void)
{
	char cdir[PATH_MAX];

	if (make_tiny_exec())
		return;

	if (!getcwd(cdir, PATH_MAX)) {
		fprintf(stderr, "Was not possible to get current working directory\n");
		return;
	}

	if (chdir(tiny.folder) < 0) {
		fprintf(stderr, "Was not possible change cwd to %s\n", tiny.folder);
		return;
	}

	if (!aslr_enabled())
		fprintf(stderr, "ASLR is not enabled\n");

	if (!pie_enabled())
		fprintf(stderr, "This binary is not PIE\n");

	if (!nx_enabled())
		fprintf(stderr, "This binary is not NX\n");

	unmake_tiny_exec();

	chdir(cdir);
}

#endif
