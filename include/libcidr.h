/*
 * libcidr.h - Header file for libCIDR
 */

#ifndef __LIBCIDR_H
#define __LIBCIDR_H

/* We need the fixed-size int types.  See discussion below. */
#include <inttypes.h>


/* CONSTANTS */
/* String forms (cidr_to_str()) */
#define CIDR_NOFLAGS        0
#define CIDR_NOCOMPACT      1 /* Don't do :: compaction */
#define CIDR_VERBOSE        1<<1 /* Don't minimize leading zeros */
#define CIDR_USEV6          1<<2 /* Use v6 form for v4 addresses */
#define CIDR_USEV4COMPAT    1<<3 /* Use v4-compat rather than v4-mapped */
#define CIDR_NETMASK		1<<4 /* Show netmask instead of pflen */
#define CIDR_NOPREFIX		1<<5 /* Don't show the prefix/mask */
#define CIDR_NOADDR			1<<6 /* Don't show the address */

/* Protocols */
#define CIDR_NOPROTO        0
#define CIDR_IPV4           1
#define CIDR_IPV6           2


/* DATA STRUCTURES */
/*
 * Discussion:
 * uint*_t are defined by POSIX and C99.  We only probably NEED stdint.h
 * defines, since we don't need the various output stuff.  However, for
 * now, we'll get all of inttypes.h because some older platforms only
 * have it, and define the uint*_t's in there (FreeBSD 4.x being the most
 * obvious one I care about).  Revisit this down the line if necessary.
 */
struct cidr_addr
{
	uint8_t	addr[16];
	uint8_t	mask[16];
	int     proto;
};
typedef struct cidr_addr CIDR;


/* PROTOTYPES */
CIDR *cidr_from_str(const char *);
int cidr_get_pflen(const CIDR *);
char *cidr_to_str(const CIDR *, int);


#endif /* __LIBCIDR_H */
