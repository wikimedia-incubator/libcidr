/*
 * Implement cidrcalc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcidr.h>

/* Width for the line defs */
#define DWID 9

char *pname;
void usage(void);

int
main(int argc, char *argv[])
{
	CIDR *addr, *addr2, *addr3;
	char *astr, *astr2;
	char boct[9];
	const char *cstr;
	int goch;
	short proto;
	short showbin;

	pname = *argv;
	showbin = 0;
	memset(boct, 0, 9);

	while((goch=getopt(argc, argv, "b"))!=-1)
	{
		switch((char)goch)
		{
			case 'b':
				showbin = 1;
				break;
			default:
				printf("Unknown argument: '%c'\n", goch);
				usage();
				/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if(argc==0)
		usage();

	/* All the rest of the args are addresses to run */
	while(*argv!=NULL)
	{
		astr = NULL;
		addr = cidr_from_str(*argv);
		if(addr ==NULL)
			printf("***> ERROR: Couldn't parse address '%s'.\n\n", *argv);
		else
		{
			/* Start putting out the pieces */
			proto = addr->proto;

			astr = cidr_to_str(addr, CIDR_ONLYADDR);
			printf("%*s: %s\n", DWID, "Address", astr);
			free(astr);

			/* Show the full 'expanded' address form */
			if(proto==CIDR_IPV6)
			{
				astr = cidr_to_str(addr,
						CIDR_VERBOSE | CIDR_NOCOMPACT | CIDR_ONLYADDR);
				printf("%*s: %s\n", DWID, "Expanded", astr);
				free(astr);
			}

			/* Show binary? */
			if(showbin==1)
			{
				printf("%*s: ", DWID, "BinAddr");
				printf("\n%*s  WRITEME\n", DWID, "");
			}

			astr = cidr_to_str(addr, CIDR_ONLYPFLEN);
			astr2 = cidr_to_str(addr, CIDR_ONLYPFLEN | CIDR_NETMASK);
			printf("%*s: %s (/%s)\n", DWID, "Netmask", astr2, astr);
			free(astr);
			free(astr2);

			astr = cidr_to_str(addr,
					CIDR_ONLYPFLEN | CIDR_NETMASK | CIDR_WILDCARD);
			/* Spaced to match above */
			printf("%*s: %s\n", DWID, "Wildcard", astr);
			free(astr);

			addr2 = cidr_addr_network(addr);
			astr = cidr_to_str(addr2, CIDR_NOFLAGS);
			printf("%*s: %s\n", DWID, "Network", astr);
			free(astr);
			cidr_free(addr2);

			addr2 = cidr_addr_broadcast(addr);
			astr = cidr_to_str(addr2, CIDR_ONLYADDR);
			printf("%*s: %s\n", DWID, "Broadcast", astr);
			free(astr);
			cidr_free(addr2);

			addr2 = cidr_addr_hostmin(addr);
			astr = cidr_to_str(addr2, CIDR_ONLYADDR);
			addr3 = cidr_addr_hostmax(addr);
			astr2 = cidr_to_str(addr3, CIDR_ONLYADDR);
			printf("%*s: %s - %s\n", DWID, "Hosts", astr, astr2);
			free(astr);
			free(astr2);
			cidr_free(addr2);
			cidr_free(addr3);

			cstr = cidr_numhost(addr);
			printf("%*s: %s\n", DWID, "NumHosts", cstr);
			/* Don't free cstr */

			/* That's it for this address */
			cidr_free(addr);
			printf("\n");
		}

		argv++;
	}

	exit(0);
}


void
usage(void)
{
	printf("Usage: %s [-b] address [...]\n"
	       "       -b  Show binary expansions\n"
	       "\n", pname);
	exit(1);
}
