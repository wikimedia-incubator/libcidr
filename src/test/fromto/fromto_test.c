/*
 * Test cidr_(from|to)_str function
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcidr.h>

int
main(int argc, char *argv[])
{
	CIDR *tcidr;
	char *tstr;

#define TESTADDR(x) \
	{ \
		tstr = NULL; \
		tcidr = cidr_from_str((x)); \
		if(tcidr==NULL) \
			printf("***> ERROR: From '%s', got NULL!!\n", (x)); \
		else \
		{ \
			tstr = cidr_to_str(tcidr, CIDR_NOFLAGS); \
			if(tcidr==NULL) \
				printf("***> ERROR: From '%s', got tcidr, got " \
						"str NULL!!\n", (x)); \
			else \
				printf("From '%s', got str '%s'.\n", (x), tstr); \
		} \
		free(tcidr); \
		free(tstr); \
	}

	TESTADDR("10.20.30.40/24");
	TESTADDR("::64.128.75.97/109");
	TESTADDR("a:b:c:d:e:f:1:2/73");
	TESTADDR("a0:bccb:931::0123:4567/73");
	TESTADDR("0:0::f08f:65/33");


	exit(0);
}
