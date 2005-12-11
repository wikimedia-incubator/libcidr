/*
 * Functions to generate various networks based on a CIDR
 */

#include <string.h>

#include <libcidr.h>


/* Get the CIDR's immediate supernet */
CIDR *
cidr_net_supernet(const CIDR *addr)
{
	int i, j;
	int pflen;
	CIDR *toret;

	/* Quick check */
	if(addr==NULL)
		return(NULL);
	
	/* If it's already a /0 in its protocol, return nothing */
	pflen = cidr_get_pflen(addr);
	if(pflen==0)
		return(NULL);
	
	toret = cidr_dup(addr);
	if(toret==NULL)
		return(NULL);
	
	/* Special case: /32 or /128; do manually */
	if(  (toret->proto==CIDR_IPV6 && pflen==128)
	  || (toret->proto==CIDR_IPV4 && pflen==32))
	{
		(toret->mask)[15] = 0xfe;
		goto post;
	}

	/* Now step through the netmask until we hit 0, and chop off a bit */
	for(i=0 ; i<=15 ; i++)
	{
		for(j=7 ; j>=0 ; j--)
		{
			/* If this is a host bit, move back one and zero */
			if( ((toret->mask)[i] & 1<<j) == 0)
			{
				if(j==7)
				{
					i--;
					j=0;
				}
				else
					j++;

				(toret->mask)[i] &= ~(1<<j);
				goto post;
			}
		}
	}

post:

	/*
	 * Now zero out the host bits.  Do this manually instead of calling
	 * cidr_addr_network() to save some extra copies and malloc()'s and
	 * so forth.
	 */
	for(i=15 ; i>=0 ; i--)
		for(j=0 ; j<=7 ; j++)
			if( ((toret->mask)[i] & 1<<j) == 0)
				(toret->addr)[i] &= ~(1<<j);
			else
				return(toret);

	/* This will only be reached if we're sending a /0 */
	return(toret);
}
