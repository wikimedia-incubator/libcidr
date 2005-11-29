/*
 * Test cidr_from_str function
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcidr.h>

int
main(int argc, char *argv[])
{
	CIDR *tcidr;
	int pflen, i, j;

	/* First, test an IPv4 address */
	printf("First v4\n\n");

#define V4_ADDR "10.20.30.40/24"
	tcidr = cidr_from_str(V4_ADDR);
	pflen=0;
	for(i=12 ; i<=15 ; i++)
		for(j=0 ; j<=7 ; j++)
			if(tcidr->mask[i] & 1<<j)
				pflen++;
	printf("From addr '%s' to '%d.%d.%d.%d/%d'\n", V4_ADDR,
			tcidr->addr[12], tcidr->addr[13], tcidr->addr[14],
			tcidr->addr[15], pflen);
	free(tcidr);


	printf("\n");


#undef V4_ADDR
#define V4_ADDR "::64.128.75.97/109"
	tcidr = cidr_from_str(V4_ADDR);
	pflen=0;
	for(i=12 ; i<=15 ; i++)
		for(j=0 ; j<=7 ; j++)
			if(tcidr->mask[i] & 1<<j)
				pflen++;
	printf("From addr '%s' to '%d.%d.%d.%d/%d'\n", V4_ADDR,
			tcidr->addr[12], tcidr->addr[13], tcidr->addr[14],
			tcidr->addr[15], pflen);
	free(tcidr);


	printf("\n\nNow v6\n\n");


#define V6_ADDR "a:b:c:d:e:f:1:2/73"
	tcidr = cidr_from_str(V6_ADDR);
	pflen=0;
	for(i=0 ; i<=15 ; i++)
		for(j=0 ; j<=7 ; j++)
			if(tcidr->mask[i] & 1<<j)
				pflen++;
	printf("From addr '%s' to '%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x/%d'\n",
			V6_ADDR,
			tcidr->addr[0], tcidr->addr[1], tcidr->addr[2], tcidr->addr[3],
			tcidr->addr[4], tcidr->addr[5], tcidr->addr[6], tcidr->addr[7],
			tcidr->addr[8], tcidr->addr[9], tcidr->addr[10], tcidr->addr[11],
			tcidr->addr[12], tcidr->addr[13], tcidr->addr[14],
			tcidr->addr[15], pflen);
	free(tcidr);


	printf("\n");


#undef V6_ADDR
#define V6_ADDR "a:b:c::f:1:2/73"
	tcidr = cidr_from_str(V6_ADDR);
	pflen=0;
	for(i=0 ; i<=15 ; i++)
		for(j=0 ; j<=7 ; j++)
			if(tcidr->mask[i] & 1<<j)
				pflen++;
	printf("From addr '%s' to '%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x/%d'\n",
			V6_ADDR,
			tcidr->addr[0], tcidr->addr[1], tcidr->addr[2], tcidr->addr[3],
			tcidr->addr[4], tcidr->addr[5], tcidr->addr[6], tcidr->addr[7],
			tcidr->addr[8], tcidr->addr[9], tcidr->addr[10], tcidr->addr[11],
			tcidr->addr[12], tcidr->addr[13], tcidr->addr[14],
			tcidr->addr[15], pflen);
	free(tcidr);



	exit(0);
}
