/*
 * Show some examples of translating to/from CIDR format
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcidr.h>

char *pname;
void usage(void);

int
main(int argc, char *argv[])
{
	CIDR *tcidr;
	char *tstr;
	int cflags, goch;

	cflags=CIDR_NOFLAGS;
	pname = *argv;
	while((goch=getopt(argc, argv, "ev6c"))!=-1)
	{
		switch((char)goch)
		{
			case 'e':
				cflags |= CIDR_NOCOMPACT;
				break;
			case 'v':
				cflags |= CIDR_VERBOSE;
				break;
			case '6':
				cflags |= CIDR_USEV6;
				break;
			case 'c':
				cflags |= (CIDR_USEV6 | CIDR_USEV4COMPAT);
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
		tstr = NULL;
		tcidr = cidr_from_str(*argv);
		if(tcidr==NULL)
			printf("***> ERROR: From '%s', got NULL!!\n", *argv);
		else
		{
			tstr = cidr_to_str(tcidr, cflags);
			if(tcidr==NULL)
				printf("***> ERROR: From '%s', got tcidr, got "
						"str NULL!!\n", *argv);
			else
				printf("From '%s', got str '%s'.\n", *argv, tstr);
		}
		free(tcidr);
		free(tstr);

		argv++;
	}

	exit(0);
}


void
usage(void)
{
	printf("Usage: %s -[ev6c] address [...]\n\n"
	       "       -e  Expand zeros instead of ::'ing [v6]\n"
	       "       -v  Show leading 0's in octets [v4/v6]\n"
	       "       -6  Use v6-mapped form for addresses [v4]\n"
	       "       -c  Use v6-compat form for addresses [v4]\n"
	       "           (implies -6)\n\n",
	       pname);
	exit(1);
}
