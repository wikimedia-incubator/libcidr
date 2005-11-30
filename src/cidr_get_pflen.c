/*
 * cidr_get_pflen() - Get the prefix length of a CIDR block
 */

#include <stdio.h>

#include <libcidr.h>

int
cidr_get_pflen(const CIDR *block)
{
	int i, j;
	int foundnmh;
	int pflen;

	/* Where do we start? */
	if(block->proto==CIDR_IPV4)
		i=12;
	else if(block->proto==CIDR_IPV6)
		i=0;
	
	/*
	 * We're intentionally not supporting non-contiguous netmasks.  So,
	 * if we find one, bomb out.
	 */
	foundnmh=0;
	pflen=0;
	for(/* i */ ; i<=15 ; i++)
	{
		for(j=7 ; j>=0 ; j--)
		{
			printf("Oct %d bit %d  ", i, j);
			if((block->mask)[i] & (1<<j))
			{
				printf("1\n");
				/*
				 * This is a network bit (1).  If we've already seen a
				 * host bit (0), we need to bomb.
				 */
				if(foundnmh==1)
					return(-1);

				pflen++;
			}
			else
			{
				printf("0\n");
				foundnmh=1; /* A host bit */
			}
		}
	}
	
	/* If we get here, return the length */
	return(pflen);
}
