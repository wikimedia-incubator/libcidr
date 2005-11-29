/*
 * Test cidr_to_str function
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcidr.h>

int
main(int argc, char *argv[])
{
	CIDR *tcidr;
	char *rstr;
	int i;

	tcidr = malloc(sizeof(CIDR));

	/* First, test an IPv4 address */
	printf("First v4\n\n");

	/* 10.20.30.40/24 */
#define V4_ADDR "10.20.30.40/24"
	memset(tcidr, 0, sizeof(CIDR));
	tcidr->proto = CIDR_IPV4;
	tcidr->addr[12] = 10;
	tcidr->addr[13] = 20;
	tcidr->addr[14] = 30;
	tcidr->addr[15] = 40;
	tcidr->mask[12] = 255;
	tcidr->mask[13] = 255;
	tcidr->mask[14] = 255;
	tcidr->mask[15] = 0;

	rstr = cidr_to_str(tcidr, CIDR_NOFLAGS);
	printf("No flags, '%s' becomes '%s'\n", V4_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_USEV6);
	printf("USEV6, '%s' becomes '%s'\n", V4_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_USEV6 | CIDR_USEV4COMPAT);
	printf("USEV6/V4COMPAT, '%s' becomes '%s'\n", V4_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_USEV6 | CIDR_VERBOSE);
	printf("USEV6/VERBOSE, '%s' becomes '%s'\n", V4_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_USEV6 | CIDR_NOCOMPACT);
	printf("USEV6/NOCOMPACT, '%s' becomes '%s'\n", V4_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_USEV6 | CIDR_NOCOMPACT | CIDR_VERBOSE);
	printf("USEV6/VERBOSE/NOCOMPACT, '%s' becomes '%s'\n", V4_ADDR, rstr);
	free(rstr);

	printf("\n\nNow v6\n\n");

	/* Now try a couple V6's */
	/* (4 0's eliminated) */
#define V6_ADDR "::ac10:445e:a14:1e28/80"
	memset(tcidr, 0, sizeof(CIDR));
	tcidr->proto = CIDR_IPV6;
	tcidr->addr[8] = 0xac;
	tcidr->addr[9] = 0x10;
	tcidr->addr[10] = 0x44;
	tcidr->addr[11] = 0x5e;
	tcidr->addr[12] = 0x0a;
	tcidr->addr[13] = 0x14;
	tcidr->addr[14] = 0x1e;
	tcidr->addr[15] = 0x28;
	for(i=0 ; i<10 ; i++)
		tcidr->mask[i] = 255;

	rstr = cidr_to_str(tcidr, CIDR_NOFLAGS);
	printf("No flags, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT);
	printf("NOCOMPACT, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_VERBOSE);
	printf("VERBOSE, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT | CIDR_VERBOSE);
	printf("NOCOMPACT/VERBOSE, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);

	printf("\n\n");

	/* (2 0's eliminated) */
#undef V6_ADDR
#define V6_ADDR "aabb:ccdd:eeff::1122:3344:66/64"
	memset(tcidr, 0, sizeof(CIDR));
	tcidr->proto = CIDR_IPV6;
	tcidr->addr[0] = 0xaa;
	tcidr->addr[1] = 0xbb;
	tcidr->addr[2] = 0xcc;
	tcidr->addr[3] = 0xdd;
	tcidr->addr[4] = 0xee;
	tcidr->addr[5] = 0xff;
	tcidr->addr[6] = 0;
	tcidr->addr[7] = 0;
	tcidr->addr[8] = 0;
	tcidr->addr[9] = 0;
	tcidr->addr[10] = 0x11;
	tcidr->addr[11] = 0x22;
	tcidr->addr[12] = 0x33;
	tcidr->addr[13] = 0x44;
	tcidr->addr[14] = 0;
	tcidr->addr[15] = 0x66;
	for(i=0 ; i<8 ; i++)
		tcidr->mask[i] = 255;

	rstr = cidr_to_str(tcidr, CIDR_NOFLAGS);
	printf("No flags, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT);
	printf("NOCOMPACT, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_VERBOSE);
	printf("VERBOSE, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT | CIDR_VERBOSE);
	printf("NOCOMPACT/VERBOSE, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);


	printf("\n\n");

	/* Now, trickier on the elimination */
#undef V6_ADDR
#define V6_ADDR "::eeff:0:0:1122:3344:66/64"
	memset(tcidr, 0, sizeof(CIDR));
	tcidr->proto = CIDR_IPV6;
	tcidr->addr[0] = 0;
	tcidr->addr[1] = 0;
	tcidr->addr[2] = 0;
	tcidr->addr[3] = 0;
	tcidr->addr[4] = 0xee;
	tcidr->addr[5] = 0xff;
	tcidr->addr[6] = 0;
	tcidr->addr[7] = 0;
	tcidr->addr[8] = 0;
	tcidr->addr[9] = 0;
	tcidr->addr[10] = 0x11;
	tcidr->addr[11] = 0x22;
	tcidr->addr[12] = 0x33;
	tcidr->addr[13] = 0x44;
	tcidr->addr[14] = 0;
	tcidr->addr[15] = 0x66;
	for(i=0 ; i<8 ; i++)
		tcidr->mask[i] = 255;

	rstr = cidr_to_str(tcidr, CIDR_NOFLAGS);
	printf("No flags, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT);
	printf("NOCOMPACT, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_VERBOSE);
	printf("VERBOSE, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT | CIDR_VERBOSE);
	printf("NOCOMPACT/VERBOSE, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);

	printf("\n\n");

	/* Another quickie */
#undef V6_ADDR
#define V6_ADDR "eeff::200/32"
	memset(tcidr, 0, sizeof(CIDR));
	tcidr->proto = CIDR_IPV6;
	tcidr->addr[0] = 0xee;
	tcidr->addr[1] = 0xff;
	tcidr->addr[14] = 0x02;
	for(i=0 ; i<4 ; i++)
		tcidr->mask[i] = 255;

	rstr = cidr_to_str(tcidr, CIDR_NOFLAGS);
	printf("No flags, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT);
	printf("NOCOMPACT, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);


	printf("\n\n");

	/* Finally, one odd case */
#undef V6_ADDR
#define V6_ADDR "0:eeff::/32"
	memset(tcidr, 0, sizeof(CIDR));
	tcidr->proto = CIDR_IPV6;
	tcidr->addr[0] = 0;
	tcidr->addr[1] = 0;
	tcidr->addr[2] = 0xee;
	tcidr->addr[3] = 0xff;
	for(i=0 ; i<4 ; i++)
		tcidr->mask[i] = 255;

	rstr = cidr_to_str(tcidr, CIDR_NOFLAGS);
	printf("No flags, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);
	rstr = cidr_to_str(tcidr, CIDR_NOCOMPACT);
	printf("NOCOMPACT, '%s' becomes '%s'\n", V6_ADDR, rstr);
	free(rstr);



	free(tcidr);
	exit(0);
}
