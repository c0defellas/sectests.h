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
 *  Tiny executable that saves the esp in addr1 and addr2 files for later analysis
 *
 *  Compiling:
 *	$ as tiny.s -o tiny.o --32
 *	$ ld -m elf_i386 tiny.o -o tiny
 *
 *  Extracting bytecode:
 *	$ hexdump -v -e '"\\""x" 1/1 "%02x" ""' tiny
 *
 *  Usage:
 *	$ ./tiny esp 1
 *      $ ./tiny esp 2
 */

	.text

.global _start

_start:
	cmp $3, (%esp)
	jne exit_error

	cld

	movl 8(%esp), %esi
	leal _esp_str, %edi
	movl $4, %ecx
	rep cmpsb
	je esp

exit_error:
	movl $1, %eax
	movl $1, %ebx
	int $0x80

esp:
	push %esp
	push %esp

	movl 20(%esp), %esi
	leal _one, %edi
	movl $2, %ecx
	rep cmpsb
	jne file2
	lea _file1_str, %ebx
	jmp write
file2:
	movl 20(%esp), %esi
	leal _two, %edi
	movl $2, %ecx
	rep cmpsb
	jne exit_error
	lea _file2_str, %ebx
write:
	movl $8, %eax
	movl $0700, %ecx
	int $0x80

	movl %eax, %ebx
	movl $4, %eax
	movl %esp, %ecx
	movl $4, %edx
	int $0x80

	movl $6, %eax
	int $0x80

	movl $1, %eax
	movl $0, %ebx
	int $0x80

.data

_esp_str:	.string "esp"
_one:		.string "1"
_two:		.string "2"
_file1_str:	.string "addr1"
_file2_str:	.string "addr2"
