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

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define ST_ASLRFLAG	0x1
#define ST_NXFLAG	0x2
#define ST_PIEFLAG	0x4
#define ST_RELROFLAG	0x8

#define ST_ERR_FORK	-0x10
#define ST_ERR_MALLOC	-0x11
#define ST_ERR_EXEC	-0x12
#define ST_ERR_PTRACE	-0x13

#define ST_PROGNAME	"/proc/self/exe"

typedef struct {
	pid_t pid;
	struct user_regs_struct regs;
	
}TRACEE_CHILD;

static inline int tracee_child_init(TRACEE_CHILD *tc){
	pid_t pid;
	
	if((pid = fork()) < 0)
		return ST_ERR_FORK;
	
	else if(!pid){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl(ST_PROGNAME, ST_PROGNAME, NULL); /* the process stops in the beginning of execl syscall */
		return ST_ERR_EXEC;
	}
	
	waitpid(pid, NULL, 0);
	
	tc->pid = pid;
	if(ptrace(PTRACE_GETREGS, pid, NULL, &tc->regs) < 0)
		return ST_ERR_PTRACE;
	
	
	return 0;
}

static inline void tracee_child_destroy(TRACEE_CHILD *tc){
	kill(tc->pid, SIGKILL);
}

static int aslr_test(void){
	TRACEE_CHILD c1, c2;
	int ret, flags;
	
	ret = tracee_child_init(&c1);
	if(ret < 0)
		return ret;
	
	ret = tracee_child_init(&c2);
	if(ret < 0)
		return ret;
	
	#if defined(__i386__)
	flags = (c1.regs.eip != c2.regs.eip) ? ST_ASLRFLAG : 0;
	
	#elif defined(__x86_64__)
	flags = (c1.regs.rip != c2.regs.rip) ? ST_ASLRFLAG : 0;
	
	#endif
	
	tracee_child_destroy(&c1);
	tracee_child_destroy(&c2);
	
	return flags;
}

static int nx_test(void){
	pid_t pid;
	int s1, s2; /* status */
	
	char stackvar[] = {'\x90', '\xc3'}; /* nop ret*/
	char *mallocvar = NULL;
	
	/* test NX stack */
	if((pid = fork()) < 0)
		return ST_ERR_FORK;
	
	else if(!pid){
		((void (*)(void))stackvar)();
		exit(0);
	}
	
	waitpid(pid, &s1, 0);

	/* test NX malloc */
	mallocvar = malloc(2);
	if(mallocvar == NULL)
		return ST_ERR_MALLOC;
	
	mallocvar[0] = '\x90'; /* nop */
	mallocvar[1] = '\xc3'; /* ret */
	
	if((pid = fork()) < 0)
		return ST_ERR_FORK;
	
	else if(!pid){
		((void (*)(void))mallocvar)();
		exit(0);
	}
	
	waitpid(pid, &s2, 0);

	return (WIFEXITED(s1) || WIFEXITED(s2)) ? 0 : ST_NXFLAG;
}

static int sectests(void){
	int secflags = 0;
	int aslr, nx;
	
	if((aslr = aslr_test()) < 0)
		return aslr;
	
	else if((nx = nx_test()) < 0)
		return nx;
	
	secflags = (aslr | nx);
	return secflags;
}

#endif
