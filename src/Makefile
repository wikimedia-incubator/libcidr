# Temporary Makefile just to handle early testing
C_FILES = \
		cidr_addr.c \
		cidr_compare.c \
		cidr_from_str.c \
		cidr_get_pflen.c \
		cidr_inaddr.c \
		cidr_mem.c \
		cidr_net.c \
		cidr_num.c \
		cidr_to_str.c
CLEAN_FILES = ${SO_FILES} ${SHLIB_NAME} ${SHLIB_LINK} *core .depend

.include "Makefile.inc"

# This need to be after the include
all build: ${SHLIB_NAME}

