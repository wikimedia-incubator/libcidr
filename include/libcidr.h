/*
 * libcidr.h - Header file for libCIDR
 */

#ifndef __LIBCIDR_H
#define __LIBCIDR_H

/* We need the fixed-size int types.  See discussion below. */
#include <inttypes.h>
/* We need the struct in[6]_addr defs */
#include <netinet/in.h>


/* CONSTANTS */
/* String forms (cidr_to_str()) */
#define CIDR_NOFLAGS        0
#define CIDR_NOCOMPACT      1 /* Don't do :: compaction */
#define CIDR_VERBOSE        1<<1 /* Don't minimize leading zeros */
#define CIDR_USEV6          1<<2 /* Use v6 form for v4 addresses */
#define CIDR_USEV4COMPAT    1<<3 /* Use v4-compat rather than v4-mapped */
#define CIDR_NETMASK		1<<4 /* Show netmask instead of pflen */
#define CIDR_ONLYADDR		1<<5 /* Only show the address */
#define CIDR_ONLYPFLEN		1<<6 /* Only show the pf/mask */

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
	int     version;
	uint8_t	addr[16];
	uint8_t	mask[16];
	int     proto;
};
typedef struct cidr_addr CIDR;


/* PROTOTYPES */
CIDR *cidr_addr_broadcast(const CIDR *);
CIDR *cidr_addr_network(const CIDR *);
CIDR *cidr_alloc(void);
int cidr_contains(const CIDR *, const CIDR *);
CIDR *cidr_dup(const CIDR *);
void cidr_free(CIDR *);
CIDR *cidr_from_inaddr(const struct in_addr *);
CIDR *cidr_from_in6addr(const struct in6_addr *);
CIDR *cidr_from_str(const char *);
int cidr_get_pflen(const CIDR *);
CIDR *cidr_net_supernet(const CIDR *);
const char *cidr_numaddr(const CIDR *);
const char *cidr_numaddr_pflen(int);
const char *cidr_numhost(const CIDR *);
const char *cidr_numhost_pflen(int);
struct in_addr *cidr_to_inaddr(const CIDR *, struct in_addr *);
struct in6_addr *cidr_to_in6addr(const CIDR *, struct in6_addr *);
char *cidr_to_str(const CIDR *, int);


#endif /* __LIBCIDR_H */
