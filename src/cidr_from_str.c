/*
 * cidr_from_str() - Generate a CIDR structure from a string in addr/len
 * form.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <libcidr.h>

CIDR *
cidr_from_str(const char *addr)
{
	size_t alen;
	CIDR *toret;
	int i, j;
	int pflen;
	int octet, nocts, eocts;

	/* Just in case */
	if(addr==NULL)
		return(NULL);

	/*
	 * Shortest possible addr would be v6 '::' (we assume max prefix
	 * length if none is given), so it better be at least 2 chars long...
	 */
	alen = strlen(addr);
	if(alen<2)
		return(NULL);
	
	toret = malloc(sizeof(CIDR));
	if(toret==NULL)
		return(NULL);
	memset(toret, 0, sizeof(CIDR));


	/*
	 * Now, let's figure out what kind of address this is.  We'll cheap
	 * out on it by going to the end, then stepping backward until we hit
	 * a . (v4) or a : (v6).
	 */
	for(i=alen-1 ; i>=0 ; i--)
	{
		if(addr[i]=='.')
		{
			toret->proto = CIDR_IPV4;
			break;
		}
		else if(addr[i]==':')
		{
			toret->proto = CIDR_IPV6;
			break;
		}
	}

	/* This shouldn't happen */
	if(toret->proto==CIDR_NOPROTO)
	{
		free(toret);
		return(NULL);
	}


	/*
	 * So now we know what sort of address it is, we can go ahead and
	 * have a parser for either.
	 */
	if(toret->proto==CIDR_IPV4)
	{
		/*
		 * Parse a v4 address.  Now, we're being a little tricksy here,
		 * and parsing it from the end instead of from the front.  This
		 * let's us ignore leading garbage (like, for instance, the
		 * address being given in v6-mapped format).
		 */

		/* First, get the prefix length */
		for(i=alen-1 ; i>=0 ; i--)
			if(addr[i]=='/')
				break;
		if(addr[i]!='/')
		{
			/* None found.  Assume /32 */
			pflen = 32;
			/* Stretch back to the end of the string */
			i=alen-1;
		}
		else
			pflen = (int)strtol(addr+i+1, NULL, 10);

		/*
		 * Now, normally, it needs to be 0...32, but we're also accepting
		 * v6-mapped forms, which can have it be 96...128.  So, cover our
		 * rears and bomb on invalid values, and canonicalize valid ones.
		 */
		if(pflen<0)
		{
			/* Always bad */
			free(toret);
			return(NULL);
		}
		if(pflen>32)
		{
			/* See if it's a 96...128 v6 mapped prefix length */
			pflen-=96;
			if(pflen<0 || pflen>32)
			{
				free(toret);
				return(NULL);
			}
		}

		/*
		 * Now pflen is in the 0...32 range and thus good.  Set it in the
		 * structure.  Note that memset zero'd the whole thing to start.
		 * We ignore mask[<12] with v4 addresses, so while a case could
		 * be made that they should be '1', I'm just leaving them alone.
		 *
		 * This is a horribly grody set of macros.  I'm only using them
		 * here to test them out before using them in the v6 section,
		 * where I'll need them more due to the sheer number of clauses
		 * I'll have to get written.  Here's the straight code I had
		 * written that the macro should be writing for me now:
		 *
		 * if(pflen>24)
		 *   for(j=24 ; j<pflen ; j++)
		 *     toret->mask[15] |= 1<<(31-j);
		 * if(pflen>16)
		 *   for(j=16 ; j<pflen ; j++)
		 *     toret->mask[14] |= 1<<(23-j);
		 * if(pflen>8)
		 *   for(j=8 ; j<pflen ; j++)
		 *     toret->mask[13] |= 1<<(15-j);
		 * if(pflen>0)
		 *   for(j=0 ; j<pflen ; j++)
		 *     toret->mask[12] |= 1<<(7-j);
		 */
#define UMIN(x,y) ((x)<(y)?(x):(y))
#define MASKNUM(x) (24-((15-x)*8))
#define WRMASKSET(x) \
	if(pflen>MASKNUM(x)) \
		for(j=MASKNUM(x) ; j<UMIN(pflen,MASKNUM(x)+8) ; j++) \
			toret->mask[x] |= 1<<(MASKNUM(x)+7-j);

		WRMASKSET(15);
		WRMASKSET(14);
		WRMASKSET(13);
		WRMASKSET(12);

#undef WRMASKET
#undef MASKNUM
#undef UMIN


		/*
		 * Now we have 4 octets to grab.  If any of 'em fail, or are
		 * outside the 0...255 range, bomb.
		 */
		nocts = 0;
		/* i-- to step before the / of the prefix */
		for( i-- ; i>=0 ; i--)
		{
			/* As long as it's still a number, move on */
			if(isdigit(addr[i]) && i>0)
				continue;

			/*
			 * It's no longer a number.  So, grab the number we just
			 * moved before.
			 */
			/* Cheat for "beginning-of-string" rather than "NaN" */
			if(i==0)
				i--;
			octet = (int)strtol(addr+i+1, NULL, 10);

			/* Sanity */
			if(octet<0 || octet>255)
			{
				free(toret);
				return(NULL);
			}

			/* Save it */
			toret->addr[15-nocts] = octet;
			nocts++;

			/*
			 * If we've got 4 of 'em, we're actually done.  We got the
			 * prefix above, so just return direct from here.
			 */
			if(nocts==4)
				return(toret);
		}

		/* If we get here, it failed to get all 4 */
		free(toret);
		return(NULL);
	}
	else if(toret->proto==CIDR_IPV6)
	{
		/*
		 * Parse a v6 address.  Like the v4, we start from the end and
		 * parse backward.  However, to handle compressed form, if we hit
		 * a ::, we drop off and start parsing from the beginning,
		 * because at the end we'll then have a hole that is what the ::
		 * is supposed to contain, which is already automagically 0 from
		 * the memset() we did earlier.  Neat!
		 */

		/* First, get the prefix length */
		for(i=alen-1 ; i>=0 ; i--)
			if(addr[i]=='/')
				break;
		if(addr[i]!='/')
		{
			/* None found.  Assume /128 */
			pflen = 128;
			/* Stretch back to the end of the string */
			i=alen-1;
		}
		else
			pflen = (int)strtol(addr+i+1, NULL, 10);

		/* Better be 0...128 */
		if(pflen<0 || pflen>128)
		{
			/* Always bad */
			free(toret);
			return(NULL);
		}

		/*
		 * Now save the pflen.  See comments on the similar code up in
		 * the v4 section about the macros.
		 */
#define UMIN(x,y) ((x)<(y)?(x):(y))
#define MASKNUM(x) (120-((15-x)*8))
#define WRMASKSET(x) \
	if(pflen>MASKNUM(x)) \
		for(j=MASKNUM(x) ; j<UMIN(pflen,MASKNUM(x)+8) ; j++) \
			toret->mask[x] |= 1<<(MASKNUM(x)+7-j);

		WRMASKSET(15);
		WRMASKSET(14);
		WRMASKSET(13);
		WRMASKSET(12);
		WRMASKSET(11);
		WRMASKSET(10);
		WRMASKSET(9);
		WRMASKSET(8);
		WRMASKSET(7);
		WRMASKSET(6);
		WRMASKSET(5);
		WRMASKSET(4);
		WRMASKSET(3);
		WRMASKSET(2);
		WRMASKSET(1);
		WRMASKSET(0);

#undef WRMASKET
#undef MASKNUM
#undef UMIN


		/*
		 * Now we have 16 octets to grab.  If any of 'em fail, or are
		 * outside the 0...0xff range, bomb.
		 */
		nocts = 0;
		/* i-- to step before the / of the prefix */
		for( i-- ; i>=0 ; i--)
		{
			/* As long as it's not our separator, keep moving */
			if(addr[i]!=':' && i>0)
				continue;

			/* If it's a :, and our NEXT char is a : too, flee */
			if(addr[i]==':' && addr[i+1]==':')
			{
				/*
				 * If i is 0, we're already at the beginning of the
				 * string, so we can just return; we've already filled in
				 * everything but the leading 0's, which are already
				 * zero-filled from the memory
				 */
				if(i==0)
					return(toret);

				/* Else, i!=0, and we break out */
				break;
			}

			/* If it's not a number either...   well, bad data */
			if(!isxdigit(addr[i]) && addr[i]!=':' && i>0)
			{
				free(toret);
				return(NULL);
			}

			/*
			 * It's no longer a number.  So, grab the number we just
			 * moved before.
			 */
			/* Cheat for "beginning-of-string" rather than "NaN" */
			if(i==0)
				i--;
			octet = (int)strtol(addr+i+1, NULL, 16);

			/* Remember, this is TWO octets */
			if(octet<0 || octet>0xffff)
			{
				free(toret);
				return(NULL);
			}

			/* Save it */
			toret->addr[15-nocts] = octet;
			nocts++;
			toret->addr[15-nocts] = octet>>8;
			nocts++;

			/* If we've got all of 'em, just return from here. */
			if(nocts==16)
				return(toret);
		}

		/*
		 * Now, if i is >=0 and we've got two :'s, jump around to the
		 * front of the string and start parsing inward.
		 */
		if(i>=0 && addr[i]==':' && addr[i+1]==':')
		{
			/* Remember how many octets we put on the end */
			eocts = nocts;

			/* Remember how far we were into the string */
			j=i;

			/* Going this way, we do things a little differently */
			i=0;
			while(i<j)
			{
				/*
				 * The first char better be a number.  If it's not, bail
				 * (a leading '::' was already handled in the loop above
				 * by just returning).
				 */
				if(i==0 && !isxdigit(addr[i]))
				{
					free(toret);
					return(NULL);
				}

				/*
				 * We should be pointing at the beginning of a digit
				 * string now.  Translate it into an octet.
				 */
				octet = (int)strtol(addr+i, NULL, 16);

				/* Sanity (again, 2 octets) */
				if(octet<0 || octet>0xffff)
				{
					free(toret);
					return(NULL);
				}

				/* Save it */
				toret->addr[nocts-eocts] = octet>>8;
				nocts++;
				toret->addr[nocts-eocts] = octet;
				nocts++;

				/*
				 * Discussion: If we're in this code block, it's because
				 * we hit a ::-compression while parsing from the end
				 * backward.  So, if we hit 15 octets here, it's an
				 * error, because with the at-least-2 that were minimized,
				 * that makes 17 total, which is too many.  So, error
				 * out.
				 */
				if(nocts==15)
				{
					free(toret);
					return(NULL);
				}

				/* Now skip around to the end of this number */
				while(isxdigit(addr[i]) && i<j)
					i++;

				/*
				 * If i==j, we're back where we started.  So we've filled
				 * in all the leading stuff, and the struct is ready to
				 * return.
				 */
				if(i==j)
					return(toret);

				/*
				 * Else, there's more to come, so skip until there IS a
				 * xdigit...
				 */
				while(!isxdigit(addr[i]) && i<j)
					i++;

				/* Ditto above */
				if(i==j)
					return(toret);

				/* Head back around */
			}
		}

		/* If we get here, it failed somewhere odd */
		free(toret);
		return(NULL);
	}
	else
	{
		/* Shouldn't happen */
		free(toret);
		return(NULL);
	}


	/* Give back the build-up struct */
	return(toret);
}
