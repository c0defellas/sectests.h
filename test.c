/*
 * test.c - simple test 
 */

#include <stdio.h>
#include "sectests.h"

int main(void)
{
	int flags = sectests();
	
	printf("ASLR [%s]\n", (flags & ST_ASLRFLAG) ? "ON": "OFF");
	printf("NX   [%s]\n", (flags & ST_NXFLAG)   ? "ON": "OFF");
	
	return 0;
}
