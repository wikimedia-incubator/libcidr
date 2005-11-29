/*
 * cidr_to_str() - Generate a textual representation of the given CIDR
 * subnet.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcidr.h>

char *
cidr_to_str(const CIDR *block, int flags)
{
	int i, j;
	short pflen;
	short lzer; /* Last zero */
	short acomp; /* Already compacted */
	char *toret;
	char tmpbuf[128]; /* We shouldn't need more than ~5 anywhere */
	CIDR *nmtmp;
	char *nmstr;

	/* Just in case */
	if( (block==NULL) || (block->proto==CIDR_NOPROTO) )
		return(NULL);
	
	/*
	 * Now, in any case, there's a maximum length for any address, which
	 * is the completely expanded form of a v4-{mapped,compat} address
	 * with a v4-/32 (v6-/128) mask.  That's 6 blocks of 4 digits (24),
	 * seperated by :'s (+5=31), followed by a : (+1=32), followed by 4
	 * octets of 3 digits (+12=44), seperated by .'s (+3=47), followed by
	 * the v6 mask (+4=51), plus the trailing null (+1=52).  Phew.
	 *
	 * I'm not, at this time anyway, going to try and allocate only and
	 * exactly as much as we need for any given address.  Whether
	 * consumers of the library can count on this behavior...  well, I
	 * haven't decided yet.  Lemme alone.
	 */
	toret = malloc(52);
	if(toret==NULL)
		return(NULL);
	memset(toret, '\0', 52);

	/*
	 * If it's a v4 address, we mask off everything but the last 4
	 * octets, and just proceed from there.
	 */
	if(block->proto==CIDR_IPV4)
	{
		/* If we're USEV6'ing, add whatever prefixes we need */
		if(flags & CIDR_USEV6)
		{
			if(flags & CIDR_NOCOMPACT)
			{
				if(flags & CIDR_VERBOSE)
					strcat(toret, "0000:0000:0000:0000:0000:");
				else
					strcat(toret, "0:0:0:0:0:");
			}
			else
				strcat(toret, "::");

			if(flags & CIDR_USEV4COMPAT)
			{
				if(flags & CIDR_NOCOMPACT)
				{
					if(flags & CIDR_VERBOSE)
						strcat(toret, "0000:");
					else
						strcat(toret, "0:");
				}
			}
			else
				strcat(toret, "ffff:");
		} /* USEV6 */

		/* Now, slap on the v4 address */
#define V4_EXTRA_BITS 12
		for(i=0 ; i<=3 ; i++)
		{
			if(flags & CIDR_VERBOSE)
				sprintf(tmpbuf, "%03u", (block->addr)[i+V4_EXTRA_BITS]);
			else
				sprintf(tmpbuf, "%u", (block->addr)[i+V4_EXTRA_BITS]);
			strcat(toret, tmpbuf);
			if(i<3)
				strcat(toret, ".");
		}

		/* And the prefix/netmask.  Which are we showing? */
		if(flags & CIDR_NETMASK)
		{
			/* In this case, we can just print out like the address above */
			strcat(toret, "/");
			for(i=0 ; i<=3 ; i++)
			{
				if(flags & CIDR_VERBOSE)
					sprintf(tmpbuf, "%03u", (block->mask)[i+V4_EXTRA_BITS]);
				else
					sprintf(tmpbuf, "%u", (block->mask)[i+V4_EXTRA_BITS]);
				strcat(toret, tmpbuf);
				if(i<3)
					strcat(toret, ".");
			}
		}
		else
		{
			/*
		 	 * For this, iterate over each octet,
		 	 * then each bit within the octet.
		 	 */
			pflen=0;
			for(i=0 ; i<=3 ; i++)
				for(j=0 ; j<=7 ; j++)
					if( (block->mask)[i+V4_EXTRA_BITS] & (1<<j) )
						pflen++;

			sprintf(tmpbuf, "/%u", (flags & CIDR_USEV6) ? pflen+96 : pflen);
			strcat(toret, tmpbuf);
		}
#undef V4_EXTRA_BITS
		
		/* That's it for a v4 address, in any of our forms */
	}
	else if(block->proto==CIDR_IPV6)
	{
		/*
		 * It's a simple, boring, normal v6 address.
		 * Now, what makes it HARD is the options we have.  To make some
		 * things simpler, we'll take two octets at a time for our run
		 * through.
		 * Note: For the moment, we're using suboptimal zero-compression
		 * in that we're just eliminating the first run of 'em.  That's
		 * just for simplicity.  We should revisit this later to get a
		 * more optimal form.
		 */
		acomp = lzer = 0;
		for(i=0 ; i<=15 ; i+=2)
		{
			/*
			 * First, if we're not the first set, we may need a : before
			 * us.  If we're not compacting, we always want it.  Even if we
			 * ARE compacting, we want it unless the previous octet was a
			 * 0 that we're minimizing.
			 */
			if(i!=0 && ((flags & CIDR_NOCOMPACT) || lzer==0))
				strcat(toret, ":");

			/*
			 * Now, if we're compacting, we haven't already compacted,
			 * and this set is zero, just skip around, UNLESS we're the
			 * first octet, in which case we should push a : onto the
			 * list so things will work out right.
			 */
			if(!(flags & CIDR_NOCOMPACT) && (block->addr)[i]==0
					&& (block->addr)[i+1]==0)
			{
				if(acomp==0)
				{
					/*
					 * Add the : if necessary, set the flag for last
					 * set being zero, and go back around the loop for
					 * the next set.
					 */
					if(i==0)
						strcat(toret, ":");
					lzer=1;
					continue;
					/* NOTREACHED */
				}
			}

			/*
			 * If lzer is set here, that can only mean we WERE
			 * compacting, and are now out of 0 sets to compact, so zero
			 * it out, set that we've already compressed, add the ending
			 * ':' for the compressed segment, and move on.
			 */
			if(lzer==1)
			{
				lzer=0;
				acomp=1;
				strcat(toret, ":");
			}

			/*
			 * From here on, we no longer have to worry about
			 * CIDR_NOCOMPACT.
			 */

			/* If we're being VERBOSE, just spit it all out */
			if(flags & CIDR_VERBOSE)
			{
				sprintf(tmpbuf, "%.2x%.2x",
						(block->addr)[i], (block->addr)[i+1]);
				strcat(toret, tmpbuf);
			}
			else
			{
				/* Not verbose, so be a little trickier. */

				/*
				 * If the first octet is non-zero, print it, with the
				 * second octet padded out to both digits.  Else, just
				 * print the second octet as it needs to be.
				 */
				if((block->addr)[i]!=0)
					sprintf(tmpbuf, "%x%.2x",
						(block->addr)[i], (block->addr)[i+1]);
				else
					sprintf(tmpbuf, "%x", (block->addr)[i+1]);

				strcat(toret, tmpbuf);
			}

			/* And loop back around to the next 2-octet set */
		} /* for(each 16-bit set) */

		/* If lzer==1, we were still minimizing, so add the extra ':' */
		if(lzer==1)
			strcat(toret, ":");

		/* Prefix/netmask */
		if(flags & CIDR_NETMASK)
		{
			/*
			 * We already wrote how to build the whole v6 form, so just
			 * call ourselves recurively for this.
			 */
			nmtmp = malloc(sizeof(CIDR));
			if(nmtmp==NULL)
			{
				free(toret);
				return(NULL);
			}
			memset(nmtmp, '0', sizeof(CIDR));
			nmtmp->proto = block->proto;
			for(i=0 ; i<=15 ; i++)
				nmtmp->addr[i] = block->mask[i];

			nmstr = cidr_to_str(nmtmp, (flags & ~CIDR_NETMASK));
			free(nmtmp);
			if(nmstr==NULL)
			{
				free(toret);
				return(NULL);
			}

			/* Strip the prefix */
			for(i=strlen(nmstr) ; i>0 ; i--)
				if(nmstr[i]=='/')
					break;
			if(i==0)
			{
				/* Shouldn't happen */
				free(toret);
				return(NULL);
			}
			nmstr[i]='\0';

			strcat(toret, "/");
			strcat(toret, nmstr);
			free(nmstr);
		}
		else
		{
			/* Just figure the and show prefix length */
			pflen=0;
			for(i=0 ; i<=15 ; i++)
				for(j=0 ; j<=7 ; j++)
					if( (block->mask)[i] & (1<<j) )
						pflen++;

			sprintf(tmpbuf, "/%u", pflen);
			strcat(toret, tmpbuf);
		}
	}
	else
	{
		/* Well, *I* dunno what the fuck it is */
		free(toret);
		return(NULL);
	}

	/* Give back the string */
	return(toret);
}
