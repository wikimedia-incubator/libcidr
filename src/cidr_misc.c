/*
 * Misc pieces
 */

#include <libcidr.h>


static const char *__libcidr_version = CIDR_VERSION_STR;

/* Library version info */
const char *
cidr_version(void)
{

	return(__libcidr_version);
}
