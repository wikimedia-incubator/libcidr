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
	
	/* Chop a bit off the netmask */
	/* This gets the first host bit */
	if(toret->proto==CIDR_IPV4)
		pflen += 96;
	i = pflen / 8;
	j = 7 - (pflen % 8);

	/* Back up one */
	if(j==7)
	{
		i--;
		j=0;
	}
	else
		j++;

	/* Make that bit a host bit */
	(toret->mask)[i] &= ~(1<<j);

	/*
	 * Now zero out the host bits in the addr.  Do this manually instead
	 * of calling cidr_addr_network() to save some extra copies and
	 * malloc()'s and so forth.
	 */
	for(/* i */ ; i<=15 ; i++)
	{
		for(/* j */ ; j>=0 ; j--)
			(toret->addr)[i] &= ~(1<<j);
		j=7;
	}

	/* And send it back */
	return(toret);
}
