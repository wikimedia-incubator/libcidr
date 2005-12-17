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

/* Gen up an octet in binary */
#define OCTET_BIN(oct) \
			{ \
				memset(boct, 0, 9); \
				for(obi = 7 ; obi>=0 ; obi--) \
					if( ((oct >> obi) & 1) == 1) \
						boct[7-obi] = '1'; \
					else \
						boct[7-obi] = '0'; \
			}

/* Show binary form of something */
#define SHOWBIN(pt, pname) \
			{ \
				printf("%*s:", DWID, "Bin" pname); \
				if(proto==CIDR_IPV4) \
				{ \
					/* Show v4 inline */ \
					for(i=12 ; i<=15 ; i++) \
					{ \
						OCTET_BIN(addr->pt[i]) \
						printf(" %s", boct); \
					} \
 	 	 	 	 	\
					/* Now skip to the same starting point */ \
					printf("\n%*s ", DWID, ""); \
 	 	 	 	 	\
					/* And show the decimal octets below */ \
					for(i=12 ; i<=15 ; i++) \
						printf(" %5d%3s", addr->pt[i], ""); \
					printf("\n"); \
				} \
				else if(proto==CIDR_IPV6) \
				{ \
					/* v6 needs to span multiple lines */ \
					for(i=0 ; i<=3 ; i++) \
					{ \
						/* 4 octets in binary */ \
						for(j=i*4 ; j<=(i*4)+3 ; j++) \
						{ \
							OCTET_BIN(addr->pt[j]) \
							printf(" %s", boct); \
						} \
						\
						/* Those 4 octets in hex */ \
						printf("\n%*s ", DWID, ""); \
						for(j=i*4 ; j<=i*4+3 ; j++) \
							printf("    %.2x   ", addr->pt[j]); \
						\
						/* Prep for next round */ \
						if(i<3) \
							printf("\n%*s ", DWID, ""); \
						else \
							printf("\n"); \
					} \
				} \
			}

/* Globals/prototypes */
char *pname;
void usage(void);

int
main(int argc, char *argv[])
{
	CIDR *addr, *addr2, *addr3;
	char *astr, *astr2;
	char boct[9];
	int obi;
	int i, j;
	const char *cstr;
	int goch;
	short proto;
	short showbin;

	pname = *argv;
	showbin = 0;

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

			/* Address */
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


			/* Netmask */
			astr = cidr_to_str(addr, CIDR_ONLYPFLEN);
			astr2 = cidr_to_str(addr, CIDR_ONLYPFLEN | CIDR_NETMASK);
			printf("%*s: %s (/%s)\n", DWID, "Netmask", astr2, astr);
			free(astr);
			free(astr2);


			/* Show binary forms? */
			if(showbin==1)
			{
				SHOWBIN(addr, "Addr")
				SHOWBIN(mask, "Mask")
			}


			/* Wildcard mask */
			astr = cidr_to_str(addr,
					CIDR_ONLYPFLEN | CIDR_NETMASK | CIDR_WILDCARD);
			/* Spaced to match above */
			printf("%*s: %s\n", DWID, "Wildcard", astr);
			free(astr);


			/* Network and broadcast */
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


			/* Range of hosts */
			addr2 = cidr_addr_hostmin(addr);
			astr = cidr_to_str(addr2, CIDR_ONLYADDR);
			addr3 = cidr_addr_hostmax(addr);
			astr2 = cidr_to_str(addr3, CIDR_ONLYADDR);
			printf("%*s: %s - %s\n", DWID, "Hosts", astr, astr2);
			free(astr);
			free(astr2);
			cidr_free(addr2);
			cidr_free(addr3);


			/* Num of hosts */
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
