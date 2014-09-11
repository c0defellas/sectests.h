/*
 *  Copyright 2014 c0defellas
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this name except in compliance with the License.
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
#include <sys/wait.h>


struct tiny
{
	char *folder;
	char *name;
	char full_path[PATH_MAX];
	int size;
	char *cmd_1[10];
	char *cmd_2[10];
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
	tiny.name = "tiny";

	strcpy(tiny.full_path, tiny.folder);
	strcat(tiny.full_path, "/");
	strcat(tiny.full_path, tiny.name);

	tiny.cmd_1[0] = tiny.full_path;
	tiny.cmd_1[1] = "esp";
	tiny.cmd_1[2] = "1";
	tiny.cmd_1[3] = NULL;

	tiny.cmd_2[0] = tiny.full_path;
	tiny.cmd_2[1] = "esp";
	tiny.cmd_2[2] = "2";
	tiny.cmd_2[3] = NULL;

	tiny.size = 460;

	fd = open(tiny.full_path, O_CREAT | O_WRONLY, S_IRWXU);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s\n", tiny.full_path);
		return -1;
	}

	written = write(fd, tiny_bytecode, tiny.size);
	if (written < tiny.size) {
		fprintf(stderr, "Written only %d of %d bytes\n", written, tiny.size);
		ret = -1;
	}

	if (close(fd) < 0)
		fprintf(stderr, "Can't close %s\n", tiny.full_path);

	return ret;
}

/* return 1 on success */
static int aslr_enabled_1(void)
{
	int pid, c1, c2;
	FILE *f1, *f2;
	char cdir[PATH_MAX];

	if (make_tiny_exec())
		return -1;

	if (!getcwd(cdir, PATH_MAX)) {
		fprintf(stderr, "Was not possible to get current working directory\n");
		return -1;
	}

	if (chdir(tiny.folder) < 0) {
		fprintf(stderr, "Was not possible to change cwd to %s\n", tiny.folder);
		return -1;
	}

	pid = fork();
	if (pid == 0) {
		execve(tiny.full_path, tiny.cmd_1, NULL);
		fprintf(stderr, "Was not possible to exec %s\n", tiny.full_path);
	}
	else if (pid < 0) {
		fprintf(stderr, "Was not possible to fork\n");
		return -1;
	}
	wait(&pid);

	pid = fork();
	if (pid == 0) {
		execve(tiny.full_path, tiny.cmd_2, NULL);
		fprintf(stderr, "Was not possible to exec %s\n", tiny.full_path);
	}
	else if (pid < 0) {
		fprintf(stderr, "Was not possible to fork\n");
		return -1;
	}
	wait(&pid);

	f1 = fopen("addr1", "r");
	if (!f1) {
		fprintf(stderr, "Was not possible to open addr1\n");
		return -1;
	}

  	f2 = fopen("addr2", "r");
	if (!f2) {
		fprintf(stderr, "Was not possible to open addr2\n");
		fclose(f1);
		return -1;
	}

	c1 = getc(f1);
	c2 = getc(f2);

	while ((c1 != EOF) && (c2 != EOF) && (c1 == c2)) {
		c1 = getc(f1);
		c2 = getc(f2);
	}

	if (fclose(f1)) {
		fprintf(stderr, "Was not possible to close addr1\n");
		exit(-1);
	}

	if (fclose(f2)) {
		fprintf(stderr, "Was not possible to close addr2\n");
		exit(-1);
	}

	if (remove("addr1") < 0)
		fprintf(stderr, "Was not possible to remove addr1\n");
	if (remove("addr2") < 0)
		fprintf(stderr, "Was not possible to remove addr2\n");
	if (remove(tiny.name) < 0)
		fprintf(stderr, "Was not possible to remove %s\n", tiny.name);

	if (chdir(cdir) < 0) {
		fprintf(stderr, "Was not possible to change cwd to %s\n", cdir);
		exit(-1);
	}

	return (c1 != c2);
}

static int aslr_enabled_2(void)
{
	tiny.folder = "/usr/bin";
	tiny.name = "awk";

	strcpy(tiny.full_path, tiny.folder);
	strcat(tiny.full_path, "/");
	strcat(tiny.full_path, tiny.name);

	tiny.cmd_1[0] = tiny.full_path;
	tiny.cmd_1[1] = "-F";
	tiny.cmd_1[2] = "-";
	tiny.cmd_1[3] = "/stack/{print $1}";
	tiny.cmd_1[4] = "/proc/self/maps";
	tiny.cmd_1[5] = NULL;

	int pid, times = 0;
	int pipefd[2];
	char buffer1[16] = {0};
	char buffer2[16] = {0};

	pipe(pipefd);

_fork:
	times++;
	pid = fork();
	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], 1);
		dup2(pipefd[1], 2);
		close(pipefd[1]);
		execv(tiny.full_path, tiny.cmd_1);
		fprintf(stderr, "Was not possible to exec %s\n", tiny.full_path);
	}
	else if (pid < 0) {
		fprintf(stderr, "Was not possible to fork\n");
		return -1;
	}

	if (times != 2) {
		read(pipefd[0], buffer1, sizeof(buffer1));
		goto _fork;
	}
	else {
		read(pipefd[0], buffer2, sizeof(buffer2));
	}
	close(pipefd[1]);

	for (int i = 0; i < 16; i++) {
		if (buffer1[i] != buffer2[i])
			return 1;
	}

	return 0;
}

static int pie_enabled(void)
{
	//search in the own elf header
	return 1;
}

static int nx_enabled(void){
	//search in the own elf header
	return 1;
}

/* Must be called from outside	*/
static void sec_tests(void)
{
	if (!aslr_enabled_2())
		fprintf(stderr, "ASLR is not enabled\n");

	if (!pie_enabled())
		fprintf(stderr, "This binary is not PIE\n");

	if (!nx_enabled())
		fprintf(stderr, "This binary is not NX\n");
}

#endif
